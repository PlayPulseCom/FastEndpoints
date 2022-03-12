using System.Reflection;
using FastEndpoints.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace FastEndpoints;

public abstract partial class Endpoint<TRequest, TResponse> : BaseEndpoint where TRequest : notnull where TResponse : notnull
{
    private static async Task<TRequest> BindToModel(HttpContext ctx, List<ValidationFailure> failures, JsonSerializerContext? serializerCtx, CancellationToken cancellation)
    {
        string? plainTextBody = null;
        IEnumerable<(string, object?)>? jsonBodyValues = null;
        if (ctx.Request.ContentLength > 0)
        {
            if (isPlainTextRequest)
            {
                plainTextBody =  await GetPlainTextBody(ctx.Request.Body).ConfigureAwait(false);
            }
            else if (ctx.Request.HasJsonContentType())
            {
                jsonBodyValues = await GetJsonBodyValuesAsync(ctx.Request, serializerCtx).ConfigureAwait(false);
            }
        }

        var properties = CreatePropertiesDictionary(
            jsonBodyValues ?? ArraySegment<(string, object?)>.Empty,
            GetFormValues(ctx.Request, failures),
            GetRouteValues(ctx.Request.RouteValues, failures),
            GetQueryParamValues(ctx.Request.Query, failures),
            GetUserClaimValues(ctx.User.Claims, failures),
            GetHeaderValues(ctx.Request.Headers, failures),
            GetHasPermissionPropertyValues(ctx.User.Claims, failures)
        );

        if (plainTextBody != null)
        {
            properties[nameof(IPlainTextRequest.Content)] = plainTextBody;
        }

        if (failures.Count > 0) throw new ValidationFailureException();

        return BuildRequest(properties, failures);
    }

    /// <remarks>
    /// Later properties will override earlier properties
    /// </remarks>
    private static Dictionary<string, object?> CreatePropertiesDictionary(params IEnumerable<(string, object?)>[] properties)
    {
        var result = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var propertiesList in properties)
        {
            foreach (var (name, value) in propertiesList)
            {
                result[name] = value;
            }
        }

        return result;
    }

    private static async Task ValidateRequest(TRequest req, HttpContext ctx, EndpointDefinition ep, object? preProcessors, List<ValidationFailure> validationFailures, CancellationToken cancellation)
    {
        if (ep.ValidatorType is null)
            return;

        var validator = (IValidator<TRequest>)ctx.RequestServices.GetRequiredService(ep.ValidatorType)!;

        var valResult = await validator.ValidateAsync(req, cancellation).ConfigureAwait(false);

        if (!valResult.IsValid)
            validationFailures.AddRange(valResult.Errors);

        if (validationFailures.Count > 0 && ep.ThrowIfValidationFails)
        {
            await RunPreprocessors(preProcessors, req, ctx, validationFailures, cancellation).ConfigureAwait(false);
            throw new ValidationFailureException();
        }
    }

    private static async Task RunPostProcessors(object? postProcessors, TRequest req, TResponse? resp, HttpContext ctx, List<ValidationFailure> validationFailures, CancellationToken cancellation)
    {
        if (postProcessors is not null)
        {
            foreach (var pp in (IPostProcessor<TRequest, TResponse>[])postProcessors)
                await pp.PostProcessAsync(req, resp, ctx, validationFailures, cancellation).ConfigureAwait(false);
        }
    }

    private static async Task RunPreprocessors(object? preProcessors, TRequest req, HttpContext ctx, List<ValidationFailure> validationFailures, CancellationToken cancellation)
    {
        if (preProcessors is not null)
        {
            foreach (var p in (IPreProcessor<TRequest>[])preProcessors)
                await p.PreProcessAsync(req, ctx, validationFailures, cancellation).ConfigureAwait(false);
        }
    }

    private static Task<string> GetPlainTextBody(Stream body)
    {
        using var streamReader = new StreamReader(body);
        return streamReader.ReadToEndAsync();
    }

    private static TRequest BuildRequest(Dictionary<string, object?> values, List<ValidationFailure> failures)
    {
        // Prefer using the constructors with the most parameters
        var constructors = tRequest.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .OrderByDescending(constructor => constructor.GetParameters().Length);
        if (!constructors.Any())
        {
            return CreateRequestWithoutConstructor(values);
        }
        
        var unbindableParameters = new List<List<string>>();
        foreach (var constructor in constructors)
        {
            if (TryBuildRequest(values, constructor, out var request, out var unbindable))
            {
                return request;
            }
            else
            {
                unbindableParameters.Add(unbindable);
            }
        }

        failures.AddRange(MissingPropertiesToValidationFailures(unbindableParameters));
        throw new ValidationFailureException();
    }

    private static bool TryBuildRequest(Dictionary<string, object?> values, ConstructorInfo constructorInfo, out TRequest request, out List<string> unbindableParameters)
    {
        var parameters = constructorInfo.GetParameters();
        unbindableParameters = parameters
            .Where(parameter => !values.ContainsKey(parameter.Name!))
            .Select(parameter => parameter.Name!)
            .ToList();
        if (unbindableParameters.Any())
        {
            request = default!;
            return false;
        }

        var (args, unused) = GetArgs(values, parameters);
        request = (TRequest) constructorInfo.Invoke(args);
        BindProperties(request, unused);
        return true;
    }

    private static TRequest CreateRequestWithoutConstructor(Dictionary<string, object?> values)
    {
        var request = (TRequest) Activator.CreateInstance(tRequest)!;
        BindProperties(request, values);
        return request;
    }

    private static IEnumerable<ValidationFailure> MissingPropertiesToValidationFailures(List<List<string>> unbindableProperties)
    {
        // TODO Could possibly allow a combination of properties that is a subset of the missing parameters across constructors
        // Naive way:
        return unbindableProperties
            .Where(x => !x.Contains("original"))
            .OrderBy(x => x.Count)
            .First()
            .Select(missingProperty => new ValidationFailure(missingProperty, "Is required"))
            .ToList();
    }

    private static (object?[] args, Dictionary<string, object?> unused) GetArgs(Dictionary<string, object?> values, ParameterInfo[] parameters)
    {
        var args = new List<object?>();
        var unused = new Dictionary<string, object?>(values);
        foreach (var parameter in parameters)
        {
            args.Add(values[parameter.Name!]);
            unused.Remove(parameter.Name!);
        }

        return (args.ToArray(), unused);
    }

    private static void BindProperties(TRequest request, Dictionary<string, object?> values)
    {
        foreach (var (name, value) in values)
        {
            var property = tRequest.GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.IgnoreCase);
            if (!property!.CanWrite)
            {
                // TODO Warn? Error? Or just skip?
                continue;
            }
            
            property.SetValue(request, value);
        }
    }

    private static async Task<IEnumerable<(string, object?)>> GetJsonBodyValuesAsync(HttpRequest request, JsonSerializerContext? ctx)
    {
        // TODO Could possibly catch json exception and return failures here
        using var streamReader = new StreamReader(request.Body);
        var topNode = JsonNode.Parse(await streamReader.ReadToEndAsync().ConfigureAwait(false));
        if (topNode == null)
        {
            return ArraySegment<(string, object?)>.Empty;
        }
        
        var cachedProps = ReqTypeCache<TRequest>.CachedProps;
        return topNode
            .AsObject()
            .Select(x => (
                x.Key,
                cachedProps.TryGetValue(x.Key, out var prop) ? x.Value?.Deserialize(prop.PropType, ctx?.Options ?? FastEndpoints.Config.SerializerOpts) : null
            ))
            .ToList();
    }

    private static Task AutoSendResponse(HttpContext ctx, TResponse? responseDto, JsonSerializerContext? jsonSerializerContext, CancellationToken cancellation)
    {
        return responseDto is null
               ? ctx.Response.SendNoContentAsync(cancellation)
               : ctx.Response.SendAsync(responseDto, 200, jsonSerializerContext, cancellation);
    }

    private static IEnumerable<(string, object?)> GetFormValues(HttpRequest httpRequest, List<ValidationFailure> failures)
    {
        if (!httpRequest.HasFormContentType)
        {
            return ArraySegment<(string, object?)>.Empty;
        }

        var formFields = httpRequest.Form.Select(kv => new KeyValuePair<string, object?>(kv.Key, kv.Value[0])).ToArray();

        var values = formFields
            .Select(formField => GetPropertyValue(formField, failures))
            .Where(value => value != null)
            .Select(value => value!.Value)
            .ToList();

        foreach (var formFile in httpRequest.Form.Files)
        {
            if (ReqTypeCache<TRequest>.CachedProps.TryGetValue(formFile.Name, out var prop))
            {
                if (prop.PropType == Types.IFormFile)
                {
                    values.Add((formFile.Name, formFile));
                }
                else
                {
                    failures.Add(new(formFile.Name, "Files can only be bound to properties of type IFormFile!"));
                }
            }
        }

        return values;
    }

    private static IEnumerable<(string, object?)> GetRouteValues(RouteValueDictionary routeValues, List<ValidationFailure> failures)
    {
        if (routeValues.Count == 0)
        {
            return ArraySegment<(string, object?)>.Empty;
        }

        var values = new List<(string, object?)>();
        foreach (var kvp in routeValues)
        {
            if ((kvp.Value as string)?.StartsWith("{") is false)
            {
                var value = GetPropertyValue(kvp, failures);
                if (value != null)
                {
                    values.Add(value.Value);
                }
            }
        }

        return values;
    }

    private static IEnumerable<(string, object?)> GetQueryParamValues(IQueryCollection query, List<ValidationFailure> failures)
    {
        return query
            .Select(kvp => GetPropertyValue(new(kvp.Key, kvp.Value[0]), failures))
            .Where(x => x.HasValue)
            .Select(x => x!.Value);
    }

    private static IEnumerable<(string, object?)> GetUserClaimValues(IEnumerable<Claim> claims, List<ValidationFailure> failures)
    {
        var values = new List<(string, object?)>();
        var cachedProps = ReqTypeCache<TRequest>.CachedFromClaimProps;

        for (int i = 0; i < cachedProps.Count; i++)
        {
            var prop = cachedProps[i];

            string? claimVal = null;
            foreach (var c in claims)
            {
                if (c.Type.Equals(prop.Identifier, StringComparison.OrdinalIgnoreCase))
                {
                    claimVal = c.Value;
                    break;
                }
            }

            if (claimVal is null && prop.ForbidIfMissing)
                failures.Add(new(prop.Identifier, "User doesn't have this claim type!"));

            if (claimVal is not null && prop.ValueParser is not null)
            {
                var (success, value) = prop.ValueParser(claimVal);
                if (success)
                {
                    values.Add((prop.PropName, value));
                }
                else
                {
                    failures.Add(new(prop.Identifier, $"Unable to bind claim value [{claimVal}] to a [{prop.PropType.Name}] property!"));
                }
            }
        }

        return values;
    }

    private static IEnumerable<(string, object?)> GetHeaderValues(IHeaderDictionary headers, List<ValidationFailure> failures)
    {
        var values = new List<(string, object?)>();
        var cachedProps = ReqTypeCache<TRequest>.CachedFromHeaderProps;

        for (int i = 0; i < cachedProps.Count; i++)
        {
            var prop = cachedProps[i];
            var hdrVal = headers[prop.Identifier].FirstOrDefault();

            if (hdrVal is null && prop.ForbidIfMissing)
                failures.Add(new(prop.Identifier, "This header is missing from the request!"));

            if (hdrVal is not null && prop.ValueParser is not null)
            {
                var (success, value) = prop.ValueParser(hdrVal);
                if (success)
                {
                    values.Add((prop.PropName, value));
                }
                else
                {
                    failures.Add(new(prop.Identifier, $"Unable to bind header value [{hdrVal}] to a [{prop.PropType.Name}] property!"));
                }
            }
        }

        return values;
    }

    private static List<(string, object?)> GetHasPermissionPropertyValues(IEnumerable<Claim> claims, List<ValidationFailure> failures)
    {
        var values = new List<(string, object?)>();
        var cachedProps = ReqTypeCache<TRequest>.CachedHasPermissionProps;

        for (int i = 0; i < cachedProps.Count; i++)
        {
            var prop = cachedProps[i];

            bool hasPerm = claims.Any(c =>
               string.Equals(c.Type, Constants.PermissionsClaimType, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(c.Value, prop.Identifier, StringComparison.OrdinalIgnoreCase));

            if (!hasPerm && prop.ForbidIfMissing)
                failures.Add(new(prop.Identifier, "User doesn't have this permission!"));

            if (hasPerm && prop.ValueParser is not null)
            {
                var (success, value) = prop.ValueParser(hasPerm);
                if (success)
                {
                    values.Add((prop.PropName, value));
                }
                else
                {
                    failures.Add(new(prop.PropName, $"Attribute [HasPermission] does not work with [{prop.PropType.Name}] properties!"));
                }
            }
        }

        return values;
    }

    private static (string, object?)? GetPropertyValue(KeyValuePair<string, object?> kvp, List<ValidationFailure> failures)
    {
        if (ReqTypeCache<TRequest>.CachedProps.TryGetValue(kvp.Key, out var prop) && prop.ValueParser is not null)
        {
            var (success, value) = prop.ValueParser(kvp.Value);
            
            if (!success)
            {
                failures.Add(new(prop.PropName, $"Unable to bind [{kvp.Value}] to a [{prop.PropType.Name}] property!"));
                return null;
            }

            return (prop.PropName, value);
        }

        return null;
    }
}