package com.pqc.analyzer.model;

public class AnalyzerRequest {
    public String repoPath;

    public AnalyzerRequest() {
    }

    public AnalyzerRequest(String repoPath) {
        this.repoPath = repoPath;
    }

    public String getRepoPath() {
        return repoPath;
    }

    public void setRepoPath(String repoPath) {
        this.repoPath = repoPath;
    }
}
