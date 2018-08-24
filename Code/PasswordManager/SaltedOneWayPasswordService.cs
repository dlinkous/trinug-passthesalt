using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace PasswordManager
{
	public class SaltedOneWayPasswordService : IPasswordService
	{
		private readonly IUserDatabase userDatabase;

		private const KeyDerivationPrf prf = KeyDerivationPrf.HMACSHA512;
		private const int iterations = 100_000;
		private const int length = 64;

		public SaltedOneWayPasswordService(IUserDatabase userDatabase) => this.userDatabase = userDatabase;

		public void Save(int userId, string password)
		{
			var salt = new byte[length];
			using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
			var hash = KeyDerivation.Pbkdf2(password, salt, prf, iterations, length);
			var saltedHash = salt.Concat(hash).ToArray();
			var saltedHashString = Convert.ToBase64String(saltedHash);
			var user = userDatabase.Read(userId);
			user.UserPass = saltedHashString;
			userDatabase.Update(user);
		}

		public bool Verify(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			var saltedHash = Convert.FromBase64String(user.UserPass);
			var salt = saltedHash.Take(length).ToArray();
			var hash = saltedHash.Skip(length).Take(length).ToArray();
			var passwordHash = KeyDerivation.Pbkdf2(password, salt, prf, iterations, length);
			return Enumerable.SequenceEqual(passwordHash, hash);
		}
	}
}
