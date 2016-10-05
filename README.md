yara-json
------------

Pretty simple proof of concept. Idea was to do basic matching of structured data.


Example rule:

```
import "json"

rule jsonrule {
    condition:
        json.kv("hello", "world")
}
```

Will match on the data:

```
{"hello":"world"}
```
