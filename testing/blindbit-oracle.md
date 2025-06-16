**Blindbit Oracle**

# [Setup](https://github.com/setavenger/blindbit-oracle/blob/master/README.md)

```
cd src/blindbit-oracle
go build -o blindbit-oracle ./src
```

#### configure blindbit.toml

```_
cp blindbit.example.toml ~/.blindbit-oracle/blindbit.toml
```

```_
host = "0.0.0.0:8000"
chain = "main"
rpc_endpoint = "http://127.0.0.1:8332"
rpc_user = "your-rpc-user"
rpc_pass = "your-rpc-password"
sync_start_height = 790000
max_parallel_tweak_computations = 8
max_parallel_requests = 8
```

**reference: https://github.com/setavenger/blindbit-oracle/blob/master/README.md*

# Testing

Date:   Wed May 7 21:35:24 2025 +0200 a6a5e87

```
go test ./src/core -v
```

**note: had to fix pathing issue in block_test.go (PR[#35](https://github.com/setavenger/blindbit-oracle/pull/35))*

```
diff --git a/src/core/block_test.go b/src/core/block_test.go
index 96e7404..f03e952 100644
--- a/src/core/block_test.go
+++ b/src/core/block_test.go
@@ -10,7 +10,7 @@ import (

 func TestBlockAnalysis(t *testing.T) {
        var block types.Block
-       err := testhelpers.LoadBlockFromFile("/Users/setorblagogee/dev/sp-test-dir/block-716120.json", &block)
+       err := testhelpers.LoadAndUnmarshalBlockFromFile("../test_data/block_833000.json", &block)
        if err != nil {
                log.Fatalln(err)
        }
```

# Execution

Start server indexing

```
./blindbit-oracle
```

*indexing data and logs are stored in ~/.blindbit-oracle/ by default*

