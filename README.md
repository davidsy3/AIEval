# AI Evaluator

AI Evaluator is a Visual Studio Code extension designed to analyze newly accepted AI-generated Python code for security vulnerabilities.

The goal of this project is to help developers identify security risks that may be introduced when using AI-generated code. After a developer accepts AI-generated code, they can run the analyzer to check the new code for supported vulnerabilities.

If a vulnerability is detected, the framework will provide:

* The type of vulnerability
* The location of the vulnerable code
* A severity level
* An explanation of why the code is vulnerable
* A suggested fix
* The code changes required to apply the fix

After the suggested fix is applied, the framework will analyze the code again and run existing functional tests to determine whether the vulnerability was removed and whether the repair introduced any regressions.

## Running the Extension

### Prerequisites

* [Node.js](https://nodejs.org/) and npm
* [Visual Studio Code](https://code.visualstudio.com/)

### Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Compile the extension:

   ```bash
   npm run compile
   ```

   To automatically recompile on file changes, use watch mode instead:

   ```bash
   npm run watch
   ```

### Launching the Extension

1. Open this folder in Visual Studio Code.
2. Press `F5` (or run **Run > Start Debugging**) to open a new Extension Development Host window with the extension loaded.
3. In the Extension Development Host window, open the Command Palette (`Cmd+Shift+P` on macOS, `Ctrl+Shift+P` on Windows/Linux) and run **AI Evaluator: Analyze for Vulnerabilities**.

## Supported Vulnerabilities

The initial version of the project will focus on Python and a predefined set of vulnerabilities, including:

* Leaked API keys or other secrets
* Command injection
* SQL injection
* Unsanitized file paths
* Vulnerable dependencies

## Project Workflow

1. A developer generates or modifies Python code using AI.
2. The developer accepts the generated code.
3. The developer runs AI Evaluator from Visual Studio Code.
4. The framework analyzes the newly accepted code.
5. Any detected vulnerability is reported with its type, location, severity, explanation, and suggested fix.
6. The developer can review and apply the suggested repair.
7. The framework checks the repaired code again.
8. Existing functional tests are run to determine whether the repair caused a regression.
9. The framework reports whether the vulnerability was removed, is still present, or whether the repair introduced a regression.

## Project Goals

The project aims to:

* Detect security vulnerabilities in newly accepted AI-generated Python code
* Clearly explain why detected code is considered vulnerable
* Provide useful and targeted repair suggestions
* Verify that suggested repairs actually remove the vulnerability
* Ensure repairs do not break existing application functionality
* Measure detection accuracy and repair effectiveness

## Success Measures

The project will evaluate its performance using the following goals:

* At least 85% detection precision
* At least 80% detection recall
* At least 80% of proposed fixes successfully remove the targeted vulnerability
* 100% of vulnerability reports include the vulnerability type, location, severity, explanation, and suggested fix
* At least 90% of successful repairs pass existing functional tests without regression

## Scope

The initial version of AI Evaluator will focus on:

* Python source code
* Newly accepted AI-generated code
* A predefined set of security vulnerabilities
* Vulnerability reporting and explanations
* Suggested repairs
* Regression testing after repairs
