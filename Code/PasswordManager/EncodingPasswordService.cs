using System;
using System.Text;

namespace PasswordManager
{
	public class EncodingPasswordService : IPasswordService
	{
		private readonly IUserDatabase userDatabase;

		public EncodingPasswordService(IUserDatabase userDatabase) => this.userDatabase = userDatabase;

		public void Save(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			user.UserPass = Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
			userDatabase.Update(user);
		}

		public bool Verify(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			return password == Encoding.UTF8.GetString(Convert.FromBase64String(user.UserPass));
		}
	}
}
