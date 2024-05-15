import * as vscode from 'vscode';
import { TrivyResult } from './explorer/trivy_result';

const diagnostics: vscode.DiagnosticCollection = vscode.languages.createDiagnosticCollection("trivy");

export const applyDiagnostics = (targetDoc: vscode.Uri, trivyResults: TrivyResult[]) => {
  console.log("Loading results");
  const d: vscode.Diagnostic[] = [];


  for (const result of trivyResults) {
    
    const startPos = new vscode.Position(result.startLine, 0);
    const endPos = new vscode.Position(result.endLine, 0);
    d.push({
      code: result.id,
      message: result.title,
      range: new vscode.Range(startPos, endPos),
      severity: vscode.DiagnosticSeverity.Error,
      source: "trivy"
    });
  }
  
  diagnostics.set(targetDoc, d);
  
};