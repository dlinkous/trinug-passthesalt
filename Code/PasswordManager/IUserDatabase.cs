using System;

namespace PasswordManager
{
	public interface IUserDatabase
	{
		void Create(User user);
		User Read(int userId);
		void Update(User user);
		void Delete(int userId);
		void DeleteAll();
	}
}
