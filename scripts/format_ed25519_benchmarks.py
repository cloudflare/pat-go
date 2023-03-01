import sys

blindgenToken = "$\\blindgen$"
blindkeyToken = "$\\blindkey$"
unblindkeyToken = "$\\unblindkey$"
blindkeySignToken = "$\\blindkeysign$"
signToken = "$\\sign$"

nameMap = {
    "BenchmarkEd25519/KeyGen": blindgenToken,
    "BenchmarkEd25519/BlindPublicKey": blindkeyToken,
    "BenchmarkEd25519/UnblindPublicKey": unblindkeyToken,
    "BenchmarkEd25519/BlindKeySign": blindkeySignToken,
    "BenchmarkEd25519/Sign": signToken,
}

orderedNames = [
    blindgenToken,
    blindkeyToken,
    unblindkeyToken,
    blindkeySignToken,
    signToken,
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
print("\\label{tab:bench-ed25519}")
print("\\caption{Computation cost for Ed25519 signing with key blinding}")
print("\\begin{tabular}{| l | c |}")
print("\hline")
print("\\textbf{Operation} & \\textbf{Time (ns/op)} \\\\ \hline")
for name in orderedNames:
    print("  %s & $%s$ \\\\ \hline" % (name, costs[name]))
print("\end{tabular}")
print("\end{table}")