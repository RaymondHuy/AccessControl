using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PrivacyABAC.WebAPI.Commands
{
    public class AccessControlCheckCommand
    {
        public string Subject { get; set; }

        public string Resource { get; set; }

        public string Environment { get; set; }

        public string Name { get; set; }

        public string Action { get; set; }
    }
}
