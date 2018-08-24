using System;
using PasswordManager.Database;

namespace PasswordManager.Tests
{
	internal class SqlConnectionStringProviderMock : ISqlConnectionStringProvider
	{
		internal string ConnectionStringValue { get; set; }

		public string ConnectionString => ConnectionStringValue;
	}
}
