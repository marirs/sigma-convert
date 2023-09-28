## SIGMAC API SERVER

This crate serves the web interface to convert the sigma files 
to various target formats.


### Deployment
When deploying set the env var `SIGMAC_API_HOST` to the address that this server is running on.  

> If the `SIGMAC_API_HOST` env var is not set it will use the default development server `http://localhost:8001`

For instance if this server is running on `https://175.15.45.12`

```ignorelang
export SIGMAC_API_HOST="https://175.15.45.12"
```

after exporting the var you can navigate to the server to use the website.

## Authors
- Sriram <marirs@gmail.com>