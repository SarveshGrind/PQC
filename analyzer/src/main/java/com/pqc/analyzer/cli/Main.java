package com.pqc.analyzer.cli;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.pqc.analyzer.baseline.BaselineScanner;
import com.pqc.analyzer.model.AnalyzerResponse;
import com.pqc.analyzer.pipeline.AnalyzerPipeline;

public class Main {
    public static void main(String[] args) {
        String repoPath = null;
        boolean runBaseline = false;

        for (int i = 0; i < args.length; i++) {
            if ("--repoPath".equals(args[i]) && i + 1 < args.length) {
                repoPath = args[++i];
            } else if ("--baseline".equals(args[i])) {
                runBaseline = true;
            }
        }

        if (repoPath == null) {
            System.err.println("Usage: java -jar analyzer-cli.jar --repoPath <path_to_repo> [--baseline]");
            System.exit(1);
        }

        AnalyzerResponse response;
        if (runBaseline) {
            BaselineScanner baseline = new BaselineScanner();
            response = baseline.run(repoPath);
        } else {
            AnalyzerPipeline pipeline = new AnalyzerPipeline();
            response = pipeline.run(repoPath);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println(gson.toJson(response));
    }
}
