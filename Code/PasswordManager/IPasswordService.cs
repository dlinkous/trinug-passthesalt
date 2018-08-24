using System;

namespace PasswordManager
{
	public interface IPasswordService
	{
		void Save(int userId, string password);
		bool Verify(int userId, string password);
	}
}
