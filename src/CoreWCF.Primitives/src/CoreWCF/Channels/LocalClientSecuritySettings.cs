// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using CoreWCF.Security;

namespace CoreWCF.Channels;

public sealed class LocalClientSecuritySettings
{
    public IdentityVerifier IdentityVerifier { get; set; }

    private LocalClientSecuritySettings(LocalClientSecuritySettings other)
    {
        this.IdentityVerifier = other.IdentityVerifier;
    }

    public LocalClientSecuritySettings()
    {
        this.IdentityVerifier = IdentityVerifier.CreateDefault();
    }

    internal LocalClientSecuritySettings Clone()
    {
        return new LocalClientSecuritySettings(this);
    }
}
