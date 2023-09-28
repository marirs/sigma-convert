# SIGMA CONVERT

This project draws inspiration from SigmaHQ for the opensource Sigma Rules. 
`Sigma Convert` can convert <b>Sigma Rules</b> to the following destination types. It can convert
a single sigma rule file or a folder of sigma rule files. There is also an API Server available,
so you can run an API Server to do conversions using Microservices.

### Supported Conversions.
The currently supported backends are:
   - ElastAlert
   - HumioAlert
   - Kibana
   - Qradar
   - Splunk
   - ArcSight
   - Chronicle
   - Devo
   - LogRhythm
   - KafkaSQL
   - AWS OpenSearch
   - DNIF
   - GrayLog
   - SQL
   - SQLite
   - Secronix
   - Sentinel
   - Snowflake
   - Sumo Logic

### Help
```bash
$ ./sigmac --help
This is the Sigma command line interface to convert Sigma rules into query languages.

Usage: sigmac [OPTIONS] --dest-type <DEST_TYPE>

Options:
  -s, --source-type <SOURCE_TYPE>
          The source target to convert from [default: sigma]
  -t, --dest-type <DEST_TYPE>
          The target type to convert to, could be arcsight, quradar, elastalert
  -f, --file-source <FILE_SOURCE>
          The source file to convert
  -d, --dir-source <DIR_SOURCE>
          The source dir to recursively convert
  -m, --mappings-file <MAPPINGS_FILE>
          The mappings.txt file for the current backend
      --keep-fields <KEEP_FIELDS>
          Keep the following list of fields in the sigma rule(comma separated). Eg "title, author, tags". `Note: This only applies to the ElastAlert dest_type`
      --replace-fields <REPLACE_FIELDS>
          Replace the following list of K:V fields in the elastalert rule (comma separated). Eg "index: tid1452-*". `Note: This only applies to the ElastAlert dest_type`
      --add-alerting <ADD_ALERTING>
          Add an alerting mode to the list in the elastalert rule. `Note: This only applies to the ElastAlert dest_type`
      --add-fields <ADD_FIELDS>
          Add extra fields in the elastalert rule if required. `Note: This only applies to the ElastAlert dest_type`
  -h, --help
          Print help
  -V, --version
          Print version

```

### Example Usage
- Convert a simple Sigma Rule to ElastAlert
```bash
$ ./sigmac --source-type sigma --dest-type elastalert --file-source ../sigmarules/T1089-\ Defense\ evasion\ \ -\ Disabling\ Security\ Tools.yml 
Converting the sigma rule in ../sigmarules/T1089- Defense evasion  - Disabling Security Tools.yml...
SUCCESS: Converted the sigma rule in ../sigmarules/T1089- Defense evasion  - Disabling Security Tools.yml to elastalert.

Output File: "~/Documents/output/elastalert_T1089- Defense evasion  - Disabling Security Tools.yml"
```

- Convert a simple Sigma Rule to ElastAlert and keep certain fields in the ElastAlert output
```bash
$ ./sigmac --dest-type elastalert --file-source ../sigmarules/T1089-\ Defense\ evasion\ \ -\ Disabling\ Security\ Tools.yml --keep-fields name,tags,impact
```

- Convert a simple Sigma Rule to ElastAlert and change/replace field values
```bash
$ ./sigmac --source-type sigma --dest-type elastalert --file-source ../sigmarules/T1089-\ Defense\ evasion\ \ -\ Disabling\ Security\ Tools.yml --replace-fields "index: newindex*"
```

- Convert a simple Sigma Rule to ElastAlert and add new fields
```bash
$ ./sigmac --dest-type elastalert --file-source ../sigmarules/T1089-\ Defense\ evasion\ \ -\ Disabling\ Security\ Tools.yml --add-fields "xyz=new_field1, abc=new_field2"
```

- Convert a simple Sigma Rule to ElastAlert and add new alerting other than debug
```bash
$ ./sigmac --dest-type elastalert --file-source ../sigmarules/T1089-\ Defense\ evasion\ \ -\ Disabling\ Security\ Tools.yml --add-alerting "Some.New.Alerting"
```

- Convert a simple Sigma Rule to a destination along with Field Mapping file.
<i><b>Use-case Scenario</b>:</i> Typically, Sigma Rule YML Files are defaulted with assumed keys.
Here you can pass a field mapping file so that you can replace the default keys to match the keys for your environment.
```bash
$ ./sigmac  --source-type <SOURCE_TYPE> --dest-type <DEST-TYPE> --file-source <FILE> --mappings_file <MAPPINGS-FILE>
```

- Convert a batch of Sigma files from a folder to ElastAlert
```bash
$ ./sigmac --source-type sigma --dest-type elastalert --dir-source ../sigmarules 
```


### Authors
Sriram <marirs@gmail.com>