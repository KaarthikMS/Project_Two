class ScanPlanner:

    def plan_scans(self, tech_stack):

        scans = ["secrets"]

        if "python" in tech_stack:
            scans.append("sast")
            scans.append("dependencies")

        if "node" in tech_stack:
            scans.append("sast")
            scans.append("dependencies")

        if "docker" in tech_stack:
            scans.append("container")

        if "terraform" in tech_stack:
            scans.append("iac")

        return scans