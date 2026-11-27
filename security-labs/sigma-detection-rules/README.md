# Sigma detection rules

Experimental Sigma rule for a narrow encoded PowerShell command indicator. Lab validation matrix: synthetic PowerShell process with `-enc` should match; ordinary PowerShell help command should not; non-PowerShell process with the same switch should not. Rule is not yet validated in sigma-cli or a SIEM. Investigate parent process, script provenance and administrator activity before escalation. This is a detection exercise, not an execution guide.

## Source

[encoded-powershell.yml](encoded-powershell.yml)

## Evidence boundary

This is a portfolio exercise. The sample is fictional; self-tests and integration validation must be run before relying on the tool in production.
