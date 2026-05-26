namespace KeyGenerator;

public interface IKeyService
{
    string CreateToken<TKey, TPayload>(Key<TKey, TPayload> key) where TKey : class;

    Result<TKey> ParseToken<TKey, TPayload>(string token) where TKey : Key<TKey, TPayload>, new();
}
