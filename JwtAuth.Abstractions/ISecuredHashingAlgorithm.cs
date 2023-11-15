namespace JwtAuth.Abstractions;

public interface ISecuredHashingAlgorithm
{
    string AlgorithmName { get; }
    string ComputeHash(string data);
}