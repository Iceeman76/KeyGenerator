namespace KeyGenerator;

public sealed record Result
{
    private Result()
    {
    }

    public required bool IsSuccess { get; init; }
    public string Problem { get; private init; } = null!;
    public static Result Success() => new() { IsSuccess = true };
    public static Result Failure(string problem) => new() { IsSuccess = false, Problem = problem };
}

public sealed record Result<TResponse>
{
    private Result()
    {
    }

    public TResponse Value { get; private init; } = default!;
    public string Problem { get; private init; } = null!;
    public required bool IsSuccess { get; init; }

    public static implicit operator Result<TResponse>(TResponse response) => Success(response);
    public static implicit operator Result<TResponse>(string problem) => Failure(problem);
    private static Result<TResponse> Success(TResponse value) => new() { IsSuccess = true, Value = value };
    private static Result<TResponse> Failure(string problem) => new() { IsSuccess = false, Problem = problem };
}
