using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordManager
{
	public class SymmetricPasswordService : IPasswordService
	{
		private readonly IUserDatabase userDatabase;

		private const string key = "nb5ZNEsUVzLWRNkk+B3cAfyo+wHpPEh1Gu7NNEG4cKQ=";

		public SymmetricPasswordService(IUserDatabase userDatabase) => this.userDatabase = userDatabase;

		public void Save(int userId, string password)
		{
			var passwordEncrypted = String.Empty;
			using (var aes = Aes.Create())
			{
				aes.Key = Convert.FromBase64String(key);
				using (var encryptor = aes.CreateEncryptor())
				using (var memoryStream = new MemoryStream())
				{
					var passwordBytes = Encoding.UTF8.GetBytes(password);
					using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
						cryptoStream.Write(passwordBytes, 0, passwordBytes.Length);
					passwordEncrypted = Convert.ToBase64String(aes.IV.Concat(memoryStream.ToArray()).ToArray());
				}
			}
			var user = userDatabase.Read(userId);
			user.UserPass = passwordEncrypted;
			userDatabase.Update(user);
		}

		public bool Verify(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			var passwordEncryptedBytes = Convert.FromBase64String(user.UserPass);
			using (var aes = Aes.Create())
			{
				aes.Key = Convert.FromBase64String(key);
				aes.IV = passwordEncryptedBytes.Take(aes.IV.Length).ToArray();
				using (var decryptor = aes.CreateDecryptor())
				using (var memoryStream = new MemoryStream(passwordEncryptedBytes.Skip(aes.IV.Length).ToArray()))
				using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
				using (var outputStream = new MemoryStream())
				{
					cryptoStream.CopyTo(outputStream);
					var passwordDecrypted = Encoding.UTF8.GetString(outputStream.ToArray());
					return password == passwordDecrypted;
				}
			}
		}
	}
}
