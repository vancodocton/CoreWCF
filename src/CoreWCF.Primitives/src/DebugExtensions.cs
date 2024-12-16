// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace CoreWCF;
public static class DebugExtensions
{
    public static void WriteXml(this XmlDocument doc)
    {
        using XmlTextWriter xmltw = new XmlTextWriter("D:\\source\\repos\\dmt\\Dmt.Demo\\WcfLabs\\test\\AcceptanceTests\\debug.xml", new System.Text.UTF8Encoding(false));
        doc.WriteTo(xmltw);
        xmltw.Close();
    }
}
