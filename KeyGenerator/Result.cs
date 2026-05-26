namespace KeyGenerator;

public record Result
{
    private string Problem { get; init; } = null!;

    public required bool IsSuccess { get; init; }

    private Result()
    {
    }

    public static Result Success() => new() { IsSuccess = true };
    public static Result Failure(string problem) => new() { IsSuccess = false, Problem = problem };

    public static implicit operator Result(string problem) => Failure(problem);

    public override string ToString() => IsSuccess ? "Ok" : Problem;
}

public record Result<TResponse>
{
    public TResponse? Value { get; private init; }
    public string Problem { get; private init; } = null!;

    public required bool IsSuccess { get; init; }
    public bool IsFailure => !IsSuccess;

    private Result()
    {
    }

    private static Result<TResponse> Success(TResponse value) => new() { IsSuccess = true, Value = value };
    private static Result<TResponse> Failure(string problem) => new() { IsSuccess = false, Problem = problem };

    public static implicit operator Result<TResponse>(TResponse response) => Success(response);
    public static implicit operator Result<TResponse>(string problem) => Failure(problem);
}
