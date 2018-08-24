using System;

namespace PasswordManager.Database
{
	public interface ISqlConnectionStringProvider
	{
		string ConnectionString { get; }
	}
}
