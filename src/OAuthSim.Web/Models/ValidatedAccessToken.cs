using System.Collections.Frozen;
using System.Text.Json;

namespace OAuthSim.Web.Models;

public sealed class ValidatedAccessToken
{
    private readonly TokenPayload payload;

    internal ValidatedAccessToken(TokenPayload payload)
    {
        this.payload = payload;
    }

    public JwtClaims Jwt => payload.Jwt;
    public AccessTokenClaims Access => payload.Access;
    public OidcAuthenticationClaims Authentication => payload.Authentication;
    public OidcProfileClaims Profile => payload.Profile;
    public SimulatorClaims Simulator => payload.Simulator;
    public IReadOnlyDictionary<string, JsonElement> CustomClaims => payload.CustomClaims;

    public IReadOnlyDictionary<string, JsonElement> ToClaims() => payload.ToClaims();

    public TokenPayload ToUserInfo() => payload with
    {
        Jwt = new JwtClaims { Subject = Jwt.Subject, NotBefore = Jwt.NotBefore },
        Access = new AccessTokenClaims(),
        Simulator = new SimulatorClaims { Country = Simulator.Country, Language = Simulator.Language },
        ExplicitNullClaims = payload.ExplicitNullClaims.Where(name => name is not
            ("iss" or "aud" or "exp" or "iat" or "jti" or "scope" or "client_id" or "token_use" or "grant_type"))
            .ToFrozenSet(StringComparer.Ordinal)
    };
}
