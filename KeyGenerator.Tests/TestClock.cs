namespace DotNetLab.KeyGenerator.Tests;

internal static class TestClock
{
    public static DateTimeOffset UtcNow { get; } = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    public static TimeProvider Provider { get; } = new FixedTimeProvider();

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
