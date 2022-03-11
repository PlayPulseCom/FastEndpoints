namespace FastEndpoints;

public class CannotBindAllParametersForConstructorsException : Exception
{
    public CannotBindAllParametersForConstructorsException(Type type, List<List<string>> unbindableParameterNames)
        : base(
            $"Cannot bind the following constructor parameters when constructing type {type.Name}: ({string.Join("), (", unbindableParameterNames.Select(parameterList => string.Join(", ", parameterList)))})")
    { }
}