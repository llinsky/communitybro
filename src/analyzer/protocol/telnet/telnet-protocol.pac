type TELNET_negotiation = record {
    negcmd      :   uint8;
};

type TELNET_nondata = record {
    command     :   uint8;
    cmd_type    :   case command of
    {
        SUBOPTION_BEGIN ->  suboption       :   TELNET_suboption;
        default         ->  negotiation     :   TELNET_negotiation;
    };
};

type TELNET_data = record {
    telnet_data :   bytestring &restofdata;
};

type TELNET_suboption = record {
    subcmd      :   uint8[] &until($element == COMMAND);
    subopt_end  :   uint8;
};

type TELNET_field = record {
    type_byte   :   uint8;
    telnet_field    :   case type_byte of 
    {
        COMMAND         ->   nondata_packet :   TELNET_nondata;
        default         ->   data_packet    :   TELNET_data;
    }; 
};

type TELNET_PDU(is_orig: bool) = record {
    telnet_fields   :   TELNET_field[] &until($input.length() == 0);
} &byteorder=bigendian;

# State tracking
refine connection TELNET_Conn += {
    %member{
        int state;
        int linemode;
        int login_checks;
        bool active_session;
        string data;
        string username;
        string password;
        bool is_orig;
        bool check_login;
    %}

    %init{
        state  = NO_EXPECT;
        linemode = TELNET_RAW;
        login_checks = 0;
        check_login = false;
        active_session = false;
    %}

    function get_orig(): bool
    %{ 
        return is_orig;
    %}

    function set_orig(o: bool): bool
    %{
        is_orig = o;
        return true;
    %}

    function get_session(): bool
    %{
        return active_session;
    %}

    function set_session(s: bool): bool
    %{
        active_session = s;
        return true;
    %}

    function get_check_login(): bool
    %{
        return check_login;
    %}

    function set_check_login(b: bool): bool
    %{
        check_login = b;
        return true;
    %}

    function get_login_checks(): int
    %{
        return login_checks;
    %}

    function set_login_checks(n: int): bool
    %{
        login_checks = n;
        return true;
    %}

    function get_state(): int
    %{
        return state;
    %}

    function set_state(s: uint8): bool
    %{
        state = s;
        return true;
    %}

    function get_data(): string
    %{
        return data;
    %} 

    function set_data(d: string): bool
    %{
        data = d;
        return true;
    %} 

    function get_last_username(): string
    %{
        return username;
    %}  

    function set_last_username(u: string): bool
    %{
        username = u;
        return true;
    %}
    
    function get_last_password(): string
    %{
        return password;
    %}  

    function set_last_password(p: string): bool
    %{
        password = p;
        return true;
    %}

    function get_linemode(): int
    %{
        return linemode;
    %}
    function set_linemode(l: int): bool
    %{
        linemode = l;
        return true;
    %}

    function clear_data(): bool
    %{
        data.clear();
        return true;
    %}

    function clear_creds(): bool
    %{
        username.clear();
        password.clear();
        return true;
    %}
};

enum TELNET_command {
    END_OF_FILE         = 236,
    SUSPEND_PROC        = 237,
    ABORT_PROC          = 238,
    END_OF_RECORD       = 239,
    SUBOPTION_END       = 240,
    NOP                 = 241,
    DATA_MARK           = 242,
    BREAK               = 243,
    INTERRUPT_PROC      = 244,
    ABORT_OUTPUT        = 245,
    ARE_YOU_THERE       = 246,
    ESC_CHAR            = 247,
    ERASE_LINE          = 248,
    GO_AHEAD            = 249,
    SUBOPTION_BEGIN     = 250,
    COMMAND             = 255
};

enum TELNET_negotiation_opts {
    WILL                = 251,
    WONT                = 252,
    DO                  = 253,
    DONT                = 254
};

enum TELNET_subcmd_opts {
    ECHO                = 1,
    SUPPRESS_GO_AHEAD   = 3,
    STATUS              = 5,
    TIMING_MARK         = 6,
    TERMINAL_TYPE       = 24,
    WINDOW_SIZE         = 31,
    TERMINAL_SPEED      = 32,
    REMOTE_FLOW_CTL     = 33,
    LINEMODE            = 34,
    ENVRMNT_VAR         = 36
};

enum TELNET_states {
    NO_EXPECT           = 0,
    EXPECT_USERNAME     = 1,
    EXPECT_PASSWORD     = 2,
    MAX_LOGIN_CHECKS    = 3,
    UNKNOWN             = 4,
    TELNET_RAW          = 8, 
    TELNET_COOKED       = 16,
    LOGIN_SUCCESS       = 32,
    LOGIN_FAIL          = 64,
    BACKSPACE           = 8
};