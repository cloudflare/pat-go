import sys

nameMap = {
    "BenchmarkPublicTokenRoundTrip/ClientRequest": "Basic Client Request",
    "BenchmarkPublicTokenRoundTrip/IssuerEvaluate": "Basic Issuer Evaluate",
    "BenchmarkPublicTokenRoundTrip/ClientFinalize": "Basic Client Finalize",
    "BenchmarkRateLimitedTokenRoundTrip/ClientRequest": "Rate-Limited Client Request",
    "BenchmarkRateLimitedTokenRoundTrip/IssuerEvaluate": "Rate-Limited Issuer Evaluate",
    "BenchmarkRateLimitedTokenRoundTrip/AttesterProcess": "Rate-Limited Attester Process",
    "BenchmarkRateLimitedTokenRoundTrip/ClientFinalize": "Rate-Limited Client Finalize",
}

orderedNames = [
    "Basic Client Request",
    "Basic Issuer Evaluate",
    "Basic Client Finalize",
    "Rate-Limited Client Request",
    "Rate-Limited Issuer Evaluate",
    "Rate-Limited Attester Process",
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
        name, cost = mapName(line[0].strip()), line[2].strip().replace("ns/op", "")
        costs[name] = cost

print("\\begin{table}[ht!]")
print("\\label{tab:bench-computation-overhead}")
print("\\caption{Computation cost for basic and rate-limited issuance protocols")
print("\\begin{tabular}{|l|c|}")
print("{\\bf Operation} & {\\bf Time (ns/op)} \hline")
print("\hline")
for name in orderedNames:
    print("  %s & $%s$ \\ \hline" % (name, costs[name]))
print("\end{tabular}")
print("\end{table}")