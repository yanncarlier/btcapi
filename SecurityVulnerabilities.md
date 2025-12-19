

Check Your Virtual Environment
If your project is running in a virtual environment, list installed packages:

```bash
source .venv/bin/activate  # On Windows: venv\Scripts\activate
pip freeze > requirements.txt
```



Use pipreqs to Auto-Detect Dependencies
If you’re unsure of the dependencies, use pipreqs to scan your project’s code:

```bash
pip install pipreqs
pipreqs . --force
```

This generates a requirements.txt based on imports in your code.



Convert requirements.txt to requirements.in by removing version numbers:

```bash
cat requirements.txt | cut -d'=' -f1 > requirements.in
```

Review requirements.in to ensure it only includes necessary packages.



- Keep requirements.in and requirements.txt in version control (e.g., Git) to track changes.

- Regularly update dependencies:

  ```bash
  pip-compile --upgrade requirements.in
  pip-audit -r requirements.txt
  
  pip install -r requirements.txt
  ```

- Consider using a tool like Dependabot (on GitHub) to automate dependency updates.