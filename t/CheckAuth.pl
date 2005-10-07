
=pod

=over 4

=item B<is_allowed_to_use_pcap()>

Returns true if the user running the test is allowed to use the packet 
capture library. On Unix systems, this function tries to open a raw socket. 
On Win32 systems (ActivePerl, Cygwin), it just checks whether the user 
has administrative privileges. 

=back

=cut

sub is_allowed_to_use_pcap {
    # Win32: ActivePerl, Cygwin
    if ($^O eq 'MSWin32' or $^O eq 'cygwin') {
        my $is_admin = 0;
        eval 'no warnings; use Win32; $is_admin = Win32::IsAdminUser()';
        $is_admin = 1 if $@; # Win32::IsAdminUser() not available
        return $is_admin

    # Unix systems
    } else {
        if(socket(S, PF_INET, SOCK_RAW, getprotobyname('icmp'))) {
            close(S);
            return 1

        } else {
            return 0
        }
    }
}

1