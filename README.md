JsonWebToken DelegatingHandler for ASP.NET WebAPI.

## Installation

    Install-Package WebApi.JsonWebToken

## Usage

Add the following to your App_Start\WebApiConfig.cs file under the Register method:

~~~csharp
config.MessageHandlers.Add(new WebApi.App_Start.JsonWebTokenValidationHandler
{
    Audience = "..your-client-id..",
    SymmetricKey = "....your-client-secret...."
});
~~~

## Documentation

For information about how to use WebApi.JsonWebToken with <a href="http://auth0.com" target="_blank">auth0</a> visit our <a href="https://docs.auth0.com/webapi" target="_blank">documentation page</a>.

## License

This client library is MIT licensed.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.
