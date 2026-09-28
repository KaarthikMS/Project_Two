import os


class RepoAnalyzer:

    def analyze(self, repo_path):

        tech_stack = []

        files = os.listdir(repo_path)

        if "package.json" in files:
            tech_stack.append("node")

        if "requirements.txt" in files or "setup.py" in files:
            tech_stack.append("python")

        if "Dockerfile" in files:
            tech_stack.append("docker")

        if any(f.endswith(".tf") for f in files):
            tech_stack.append("terraform")

        if any(f.endswith(".java") for f in files):
            tech_stack.append("java")

        return tech_stack