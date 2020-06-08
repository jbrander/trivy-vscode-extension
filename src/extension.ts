// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from "vscode";

export function trivyCommand(projectRootPath: string): string {
  console.log(projectRootPath);

  var child_process = require("child_process");
  try {
    return child_process
      .execSync("trivy filesystem --exit-code=10 " + projectRootPath)
      .toString();
  } catch (result) {
    switch (result.status) {
      case 0: {
        vscode.window.showInformationMessage("No vulnerabilities found.");
        return "";
      }
      case 10: {
        vscode.window.showErrorMessage("Vulnerabilities found, check logs");
        return result.stdout.toString();
      }
      default: {
        vscode.window.showErrorMessage(
          "Failed to run Trivy scan, error: " +
            result.status +
            " check logs for details."
        );
        return result.stdout.toString();
      }
    }
    // console.log(error.stdout);
  }
}

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
  // This line of code will only be executed once when your extension is activated
  console.log('Congratulations, your extension "trivy-vulnerability-scanner" is now active!');

  var outputChannel = vscode.window.createOutputChannel("trivy");

  const editor = vscode.window.activeTextEditor;
  if (editor === undefined) {
    // vscode.window.showErrorMessage("Please select ");
    return;
  }

  const projectRootPath = vscode.workspace.getWorkspaceFolder(
    editor.document.uri
  );

  if (projectRootPath === undefined) {
    vscode.window.showErrorMessage("Unable to find project root path");
    return;
  }

  // The command has been defined in the package.json file
  // Now provide the implementation of the command with registerCommand
  // The commandId parameter must match the command field in package.json
  let disposable = vscode.commands.registerCommand("trivy-vulnerability-scanner.scan", () => {
    // The code you place here will be executed every time your command is executed

    var result = trivyCommand(projectRootPath.uri.fsPath.toString());
    if (result.length > 0) {
      // outputChannel.show(); // TODO: Un-comment if logs should automatically appear
      outputChannel.appendLine(result);
    }
    context.subscriptions.push(disposable);
  });
}

// this method is called when your extension is deactivated
export function deactivate() {}
