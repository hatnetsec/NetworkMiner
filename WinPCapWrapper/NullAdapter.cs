//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkWrapper {
    public class NullAdapter : IAdapter{

        public override string ToString() {
            return "--- Select a network adapter in the list ---";
        }
    }
}
