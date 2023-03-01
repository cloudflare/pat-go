import sys

nameMap = {
    "BenchmarkPublicTokenRoundTrip/ClientRequest": "Basic Client Request",
    "BenchmarkPublicTokenRoundTrip/IssuerEvaluate": "Basic Issuer Evaluate",
    "BenchmarkPublicTokenRoundTrip/ClientFinalize": "Basic Client Finalize",
    "BenchmarkRateLimitedTokenRoundTrip/ClientRequest": "Rate-Limited Client Request",
    "BenchmarkRateLimitedTokenRoundTrip/AttesterRequest": "Rate-Limited Attester Request",
    "BenchmarkRateLimitedTokenRoundTrip/IssuerEvaluate": "Rate-Limited Issuer Evaluate",
    "BenchmarkRateLimitedTokenRoundTrip/AttesterEvaluate": "Rate-Limited Attester Evaluate",
    "BenchmarkRateLimitedTokenRoundTrip/ClientFinalize": "Rate-Limited Client Finalize",
}

orderedNames = [
    "Basic Client Request",
    "Basic Issuer Evaluate",
    "Basic Client Finalize",
    "Rate-Limited Client Request",
    "Rate-Limited Attester Request",
    "Rate-Limited Issuer Evaluate",
    "Rate-Limited Attester Evaluate",
    "Rate-Limited Client Finalize",
]

def mapName(name):
    for key in nameMap:
        if name.startswith(key):
            return nameMap[key]
    raise Exception("Unknown operation", name)

costs = {}
for line in sys.stdin:
    if line.startswith("Benchmark"):
        line = line.strip().split("\t")
        try:
            name, cost = mapName(line[0].strip()), line[2].strip().replace("ns/op", "")
            costs[name] = cost
        except:
            # Ignore other benchmarks
            pass

print("\\begin{table}[ht!]")
print("\\label{tab:bench-computation-overhead}")
print("\\caption{Computation cost for basic and rate-limited issuance protocols}")
print("\\begin{tabular}{| l | c |}")
print("\hline")
print("\\textbf{Operation} & \\textbf{Time (ns/op)} \\\\ \hline")
for name in orderedNames:
    print("  %s & $%s$ \\\\ \hline" % (name, costs[name]))
print("\end{tabular}")
print("\end{table}")