ArangoDB.AspNetCore.Identity
=======================

ASP.NET Core Identity provider that uses ArangoDB for storage

## Purpose ##

This provider acts as a replacement/plugin for the default AspNetCore Identity Framework using ArangoDB as the backend.
This project relies on the fantastic [ArangoClient.NET](https://github.com/ra0o0f/arangoclient.net) by [ra0o0f](https://github.com/ra0o0f)
for connectivity and will be updated as that library is updated.

## Installation ##

```
Install-Package ArangoDB.AspNetCore.Identity
```

## Features ##
* Drop-in replacement ASP.NET Identity with ArangoDB as the backing store.
* Requires only 2 ArangoDB document type, while EntityFramework requires 5 tables
* Contains the same IdentityUser class used by the EntityFramework provider in the MVC 5 project template.
* Supports additional profile properties on your application's user model.
