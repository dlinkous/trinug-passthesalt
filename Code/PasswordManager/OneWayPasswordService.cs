using System;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace PasswordManager
{
	public class OneWayPasswordService : IPasswordService
	{
		private readonly IUserDatabase userDatabase;

		private const KeyDerivationPrf prf = KeyDerivationPrf.HMACSHA512;
		private const int iterations = 100_000;
		private const int length = 64;

		public OneWayPasswordService(IUserDatabase userDatabase) => this.userDatabase = userDatabase;

		public void Save(int userId, string password)
		{
			var hashBytes = KeyDerivation.Pbkdf2(password, Encoding.UTF8.GetBytes(password), prf, iterations, length);
			var hash = Convert.ToBase64String(hashBytes);
			var user = userDatabase.Read(userId);
			user.UserPass = hash;
			userDatabase.Update(user);
		}

		public bool Verify(int userId, string password)
		{
			var hashBytes = KeyDerivation.Pbkdf2(password, Encoding.UTF8.GetBytes(password), prf, iterations, length);
			var hash = Convert.ToBase64String(hashBytes);
			var user = userDatabase.Read(userId);
			return hash == user.UserPass;
		}
	}
}
