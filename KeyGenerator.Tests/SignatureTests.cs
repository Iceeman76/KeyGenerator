using DotNetLab.KeyGenerator.Signatures;

namespace DotNetLab.KeyGenerator.Tests;

public sealed class SignatureTests
{
    [Test]
    public void Symmetric256_ShouldMatchRfc4231TestCase2()
    {
        var signature = new Symmetric256().Generate("what do ya want for nothing?", "Jefe");

        Assert.That(Convert.ToHexString(signature), Is.EqualTo("5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"));
    }

    [Test]
    public void Symmetric512_ShouldMatchRfc4231TestCase2()
    {
        var signature = new Symmetric512().Generate("what do ya want for nothing?", "Jefe");

        Assert.That(Convert.ToHexString(signature), Is.EqualTo("164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737"));
    }

    [Test]
    public void Symmetric64_ShouldMatchFirstEightBytesOfRfc4231TestCase2()
    {
        var signature = new Symmetric64().Generate("what do ya want for nothing?", "Jefe");

        Assert.That(Convert.ToHexString(signature), Is.EqualTo("5BDCC146BF60754E"));
    }
}
