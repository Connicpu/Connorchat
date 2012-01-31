using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ConnorcpuChatServer {
    class Authentication {

        internal static UserAuthResult Authenticate(string user, string pass) {


            return UserAuthResult.NonexistantUser;
        }

        
    }

    [Flags]
    enum UserAuthResult {
        Success,
        WrongPassword,
        NonexistantUser,
        Banned
    }
}
