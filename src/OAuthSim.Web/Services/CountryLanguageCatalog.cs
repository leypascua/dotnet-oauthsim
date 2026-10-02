using System.Globalization;
using System.Text.Json;

namespace OAuthSim.Web.Services;

public sealed record CountryOption(string Code, string Name, string[] Languages);

public sealed class CountryLanguageCatalog
{
    public IReadOnlyList<CountryOption> Countries { get; }
    public CountryLanguageCatalog()
    {
        using var stream = typeof(CountryLanguageCatalog).Assembly.GetManifestResourceStream("OAuthSim.Web.Resources.country-languages.json")!;
        var data = JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
        Countries = data.Select(p => new CountryOption(p.Key, CountryName(p.Key), p.Value.Split(' ').Append("en").Distinct().ToArray()))
            .OrderBy(c => c.Name, StringComparer.Ordinal).ToArray();
    }
    public bool IsValid(string country, string language) => Countries.Any(c => c.Code == country && c.Languages.Contains(language));
    public static string LanguageName(string code)
    {
        try { return CultureInfo.GetCultureInfo(code).EnglishName; }
        catch (CultureNotFoundException) { return code; }
    }
    private static string CountryName(string code)
    {
        try { return new RegionInfo(code).EnglishName; }
        catch (ArgumentException) { return code; }
    }
}
