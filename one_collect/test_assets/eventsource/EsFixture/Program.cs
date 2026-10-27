using System.Diagnostics.Tracing;

// Test fixture for one_collect EventSource in-band manifest decoding.
//   EsFixture manifest <path>       write the generated manifest XML
//   EsFixture emit <seconds>        emit known events (manifest mode + one TraceLogging event)
if (args.Length >= 2 && args[0] == "manifest")
{
    string xml = EventSource.GenerateManifest(typeof(TestSource), "OneCollectTest.dll")!;
    File.WriteAllText(args[1], xml, new System.Text.UTF8Encoding(false));
    Console.WriteLine($"wrote {xml.Length} chars, guid {EventSource.GetGuid(typeof(TestSource))}");
    return;
}

if (args.Length >= 2 && args[0] == "emit")
{
    int seconds = int.Parse(args[1]);
    using var src = TestSource.Log;
    Console.WriteLine($"provider {src.Name} {src.Guid}");
    var deadline = DateTime.UtcNow.AddSeconds(seconds);
    while (DateTime.UtcNow < deadline)
    {
        src.AllScalars(-8, 0xAB, -1600, 0xBEEF, -32000000, 0xDEADBEEF, -6400000000000L, 0x0102030405060708UL, 3.5f, 2.25, true, 'Z');
        src.Strings("hello-inband", "", 1234);
        src.Misc(new Guid("12345678-9abc-def0-1122-334455667788"), new DateTime(2021, 7, 1, 12, 34, 56, DateTimeKind.Utc), new IntPtr(0x1234), TestColor.Green);
        src.Blob(7, new byte[] { 1, 2, 3, 4, 5 }, 9);
        src.Ping();
        src.RequestStart(42);
        src.RequestStop(42);
        src.Versioned(77);
        src.Write("MixedTl", new { Value = 4242 });
        Thread.Sleep(200);
    }
    return;
}

Console.Error.WriteLine("usage: EsFixture manifest <path> | emit <seconds>");
Environment.Exit(2);

public enum TestColor { Red = 0, Green = 1, Blue = 2 }

[EventSource(Name = "OneCollect-Test-InbandManifest")]
public sealed class TestSource : EventSource
{
    public static readonly TestSource Log = new TestSource();

    private TestSource() : base(EventSourceSettings.EtwManifestEventFormat) { }

    public static class Tasks { public const EventTask Request = (EventTask)1; }

    [Event(1, Level = EventLevel.Informational)]
    public void AllScalars(sbyte s8, byte u8, short s16, ushort u16, int s32, uint u32, long s64, ulong u64, float f32, double f64, bool b, char c)
        => WriteEvent(1, s8, u8, s16, u16, s32, u32, s64, u64, f32, f64, b, c);

    [Event(2, Level = EventLevel.Informational)]
    public void Strings(string first, string empty, int after) => WriteEvent(2, first, empty, after);

    [Event(3, Level = EventLevel.Informational)]
    public void Misc(Guid g, DateTime when, IntPtr ptr, TestColor color) => WriteEvent(3, g, when, ptr, color);

    [Event(4, Level = EventLevel.Informational)]
    public void Blob(int before, byte[] data, int after) => WriteEvent(4, before, data, after);

    [Event(5, Level = EventLevel.Informational)]
    public void Ping() => WriteEvent(5);

    [Event(6, Level = EventLevel.Informational, Opcode = EventOpcode.Start, Task = Tasks.Request)]
    public void RequestStart(int requestId) => WriteEvent(6, requestId);

    [Event(7, Level = EventLevel.Informational, Opcode = EventOpcode.Stop, Task = Tasks.Request)]
    public void RequestStop(int requestId) => WriteEvent(7, requestId);

    [Event(8, Level = EventLevel.Informational, Version = 2)]
    public void Versioned(int value) => WriteEvent(8, value);
}
