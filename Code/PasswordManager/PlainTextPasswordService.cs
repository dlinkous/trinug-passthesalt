using System;

namespace PasswordManager
{
	public class PlainTextPasswordService : IPasswordService
	{
		private readonly IUserDatabase userDatabase;

		public PlainTextPasswordService(IUserDatabase userDatabase) => this.userDatabase = userDatabase;

		public void Save(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			user.UserPass = password;
			userDatabase.Update(user);
		}

		public bool Verify(int userId, string password)
		{
			var user = userDatabase.Read(userId);
			return password == user.UserPass;
		}
	}
}
