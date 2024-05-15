import * as vscode from 'vscode';
import * as child from 'child_process';
import { v4 as uuid } from 'uuid';
import * as path from 'path';
import { unlinkSync, readdirSync, existsSync, readFileSync} from 'fs';
import { applyDiagnostics } from './diagnostics'; 
import { processResult } from './explorer/trivy_result';

export class TrivyWrapper {
    private workingPath: string[] = [];
    constructor(
        private outputChannel: vscode.OutputChannel,
        private readonly resultsStoragePath: string) {
        if (!vscode.workspace || !vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length <= 0) {
            return;
        }
        const folders = vscode.workspace.workspaceFolders;
        for (let i = 0; i < folders.length; i++) {
            if (folders[i]) {
                const workspaceFolder = folders[i];
                if (!workspaceFolder) {
                    continue;
                }
                this.workingPath.push(workspaceFolder.uri.fsPath);
            }
        }
    }

    run(targetFile?: vscode.Uri) {
        if (targetFile) {
            this.fileScan(targetFile);
        } else {
            this.workspaceScan();
        }
    }

    showCurrentTrivyVersion() {
        const currentVersion = this.getInstalledTrivyVersion();
        if (currentVersion) {
            vscode.window.showInformationMessage(`Current Trivy version is ${currentVersion}`);
        }
    }

    private workspaceScan(){
        let outputChannel = this.outputChannel;
        this.outputChannel.appendLine("");
        this.outputChannel.appendLine("Running Trivy to update results");

        if (!this.checkTrivyInstalled()) {
            return;
        }

        var files = readdirSync(this.resultsStoragePath).filter(fn => fn.endsWith('_results.json') || fn.endsWith('_results.json.json'));
        files.forEach(file => {
            let deletePath = path.join(this.resultsStoragePath, file);
            unlinkSync(deletePath);
        });

        const binary = this.getBinaryPath();

        this.workingPath.forEach(workingPath => {
            let command = this.buildCommand(workingPath);
            this.outputChannel.appendLine(`command: ${command}`);

            var execution = child.spawn(binary, command);

            execution.stdout.on('data', function (data) {
                outputChannel.appendLine(data.toString());
            });

            execution.stderr.on('data', function (data) {
                outputChannel.appendLine(data.toString());
            });

            execution.on('exit', function (code) {
                if (code !== 0) {
                    vscode.window.showErrorMessage("Trivy failed to run");
                    return;
                };
                vscode.window.showInformationMessage('Trivy ran successfully, updating results');
                outputChannel.appendLine('Reloading the Findings Explorer content');
                setTimeout(() => { vscode.commands.executeCommand("trivy-vulnerability-scanner.refresh"); }, 250);
            });
        });
    }

    private fileScan(targetFile: vscode.Uri) {

        if (!this.checkTrivyInstalled()) {
            return;
        }
        const outputFn = `${uuid()}_results.json`;
        const resultFile = path.join(this.resultsStoragePath, outputFn);
        const binary = this.getBinaryPath();

        let command = this.buildCommand(targetFile.fsPath, outputFn);
        this.outputChannel.appendLine(`command: ${command}`);

        var execution = child.spawn(binary, command);


        execution.on('exit', function (code) {
            if (code !== 0) {
                console.log("Trivy failed to run");
                return;
            };
            
            setTimeout(() => { 				
                if (!existsSync(resultFile)){ return; }

                let content = readFileSync(resultFile, 'utf8');
                try {
                    const data = JSON.parse(content);
                    if (data === null || data.results === null) {
                        return;
                    }
                    console.log(path.basename(targetFile.fsPath));
                    for(let i = 0; i < data.Results.length; i++){                        
                        if (data.Results[i].Target.includes(path.basename(targetFile.fsPath))){
                            let results = processResult(data.Results[i]); 
                            applyDiagnostics(targetFile, results);
                        }
                    }                               
                }	catch (error) {
                    console.debug(`Error loading results file ${resultFile}: ${error}`);
                }
                
                }, 250);
        });
    }

    private getBinaryPath() {
        const config = vscode.workspace.getConfiguration('trivy');
        var binary = config.get('binaryPath', 'trivy');
        if (binary === "") {
            binary = "trivy";
        }

        return binary;
    };

    private checkTrivyInstalled(): boolean {
        const binaryPath = this.getBinaryPath();

        var command = [];
        command.push(binaryPath);
        command.push('--help');
        try {
            child.execSync(command.join(' '));
        }
        catch (err) {
            this.outputChannel.show();
            this.outputChannel.appendLine(`Trivy not found. Check the Trivy extension settings to ensure the path is correct. [${binaryPath}]`);
            return false;
        }
        return true;
    };

    private getInstalledTrivyVersion(): string {

        if (!this.checkTrivyInstalled) {
            vscode.window.showErrorMessage("Trivy could not be found, check Output window");
            return "";
        }

        let binary = this.getBinaryPath();

        var command = [];
        command.push(binary);
        command.push('--version');
        const getVersion = child.execSync(command.join(' '));
        return getVersion.toString();
    };


    private buildCommand(workingPath: string, outputFn?: string): string[] {
        const config = vscode.workspace.getConfiguration('trivy');
        var command = [];

        if (typeof(outputFn) !== 'string' || outputFn.length < 1 || path.extname(outputFn) !== '.json'){
            outputFn = `${uuid()}_results.json`;
        }

        if (config.get<boolean>('debug')) {
            command.push('--debug');
        }

        let requireChecks = "config,vuln";
        if (config.get<boolean>("secretScanning")) {
            requireChecks = `${requireChecks},secret`;
        }
        command.push("fs");
        command.push(`--security-checks=${requireChecks}`);
        command.push(this.getRequiredSeverities(config));

        if (config.get<boolean>("offlineScan")) {
            command.push('--offline-scan');
        }

        if (config.get<boolean>("fixedOnly")) {
            command.push('--ignore-unfixed');
        }

        if (config.get<boolean>("server.enable")) {
            command.push('--server');
            command.push(`${config.get<string>("server.url")}`);
        }

        

        command.push('--format=json');
        const resultsPath = path.join(this.resultsStoragePath, outputFn);
        command.push(`--output=${resultsPath}`);

        command.push(workingPath);
        return command;
    }


    private getRequiredSeverities(config: vscode.WorkspaceConfiguration): string {

        let requiredSeverities: string[] = [];

        const minRequired = config.get<string>("minimumReportedSeverity");
        const severities: string[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

        for (let i = 0; i < severities.length; i++) {
            const s = severities[i];
            if (!s) {
                continue;
            }
            requiredSeverities.push(s);
            if (s === minRequired) {
                break;
            }
        }

        return `--severity=${requiredSeverities.join(",")}`;
    }
}


