defmodule :m_otp_internal do
  use Bitwise

  def obsolete(:auth, :cookie, 0) do
    {:deprecated, ~c"use erlang:get_cookie/0 instead"}
  end

  def obsolete(:auth, :cookie, 1) do
    {:deprecated, ~c"use erlang:set_cookie/2 instead"}
  end

  def obsolete(:auth, :is_auth, 1) do
    {:deprecated, ~c"use net_adm:ping/1 instead"}
  end

  def obsolete(:calendar, :local_time_to_universal_time, 1) do
    {:deprecated, ~c"use calendar:local_time_to_universal_time_dst/1 instead"}
  end

  def obsolete(:crypto, :crypto_dyn_iv_init, 3) do
    {:deprecated, ~c"see the documentation for details", ~c"OTP 27"}
  end

  def obsolete(:crypto, :crypto_dyn_iv_update, 3) do
    {:deprecated, ~c"see the documentation for details", ~c"OTP 27"}
  end

  def obsolete(:crypto, :rand_uniform, 2) do
    {:deprecated, ~c"use rand:uniform/1 instead"}
  end

  def obsolete(:dbg, :stop_clear, 0) do
    {:deprecated, ~c"use dbg:stop/0 instead", ~c"OTP 27"}
  end

  def obsolete(:disk_log, :inc_wrap_file, 1) do
    {:deprecated, ~c"use disk_log:next_file/1 instead", ~c"OTP 28"}
  end

  def obsolete(:erlang, :now, 0) do
    {:deprecated,
     ~c"see the \"Time and Time Correction in Erlang\" chapter of the ERTS User's Guide for more information"}
  end

  def obsolete(:erlang, :phash, 2) do
    {:deprecated, ~c"use erlang:phash2/2 instead"}
  end

  def obsolete(:file, :pid2name, 1) do
    {:deprecated, ~c"this functionality is no longer supported", ~c"OTP 27"}
  end

  def obsolete(:http_uri, :decode, 1) do
    {:deprecated, ~c"use uri_string:unquote function instead", ~c"OTP 27"}
  end

  def obsolete(:http_uri, :encode, 1) do
    {:deprecated, ~c"use uri_string:quote function instead", ~c"OTP 27"}
  end

  def obsolete(:httpd, :parse_query, 1) do
    {:deprecated, ~c"use uri_string:dissect_query/1 instead"}
  end

  def obsolete(:net, :broadcast, 3) do
    {:deprecated, ~c"use rpc:eval_everywhere/3 instead"}
  end

  def obsolete(:net, :call, 4) do
    {:deprecated, ~c"use rpc:call/4 instead"}
  end

  def obsolete(:net, :cast, 4) do
    {:deprecated, ~c"use rpc:cast/4 instead"}
  end

  def obsolete(:net, :ping, 1) do
    {:deprecated, ~c"use net_adm:ping/1 instead"}
  end

  def obsolete(:net, :sleep, 1) do
    {:deprecated, ~c"use 'receive after T -> ok end' instead"}
  end

  def obsolete(:queue, :lait, 1) do
    {:deprecated, ~c"use queue:liat/1 instead"}
  end

  def obsolete(:sys, :get_debug, 3) do
    {:deprecated,
     ~c"incorrectly documented and only for internal use. Can often be replaced with sys:get_log/1"}
  end

  def obsolete(:wxCalendarCtrl, :enableYearChange, 1) do
    {:deprecated, ~c"not available in wxWidgets-2.9 and later"}
  end

  def obsolete(:wxCalendarCtrl, :enableYearChange, 2) do
    {:deprecated, ~c"not available in wxWidgets-2.9 and later"}
  end

  def obsolete(:zlib, :adler32, 2) do
    {:deprecated, ~c"use erlang:adler32/1 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :adler32, 3) do
    {:deprecated, ~c"use erlang:adler32/2 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :adler32_combine, 4) do
    {:deprecated, ~c"use erlang:adler_combine/3 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :crc32, 1) do
    {:deprecated, ~c"use erlang:crc32/1 on the uncompressed data instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :crc32, 2) do
    {:deprecated, ~c"use erlang:crc32/1 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :crc32, 3) do
    {:deprecated, ~c"use erlang:crc32/2 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :crc32_combine, 4) do
    {:deprecated, ~c"use erlang:crc32_combine/3 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :getBufSize, 1) do
    {:deprecated, ~c"this function will be removed in a future release", ~c"OTP 27"}
  end

  def obsolete(:zlib, :inflateChunk, 1) do
    {:deprecated, ~c"use safeInflate/2 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :inflateChunk, 2) do
    {:deprecated, ~c"use safeInflate/2 instead", ~c"OTP 27"}
  end

  def obsolete(:zlib, :setBufSize, 2) do
    {:deprecated, ~c"this function will be removed in a future release", ~c"OTP 27"}
  end

  def obsolete(:code, :is_module_native, 1) do
    {:removed, ~c"HiPE has been removed"}
  end

  def obsolete(:code, :rehash, 0) do
    {:removed, ~c"the code path cache feature has been removed"}
  end

  def obsolete(:core_lib, :get_anno, 1) do
    {:removed, ~c"use cerl:get_ann/1 instead"}
  end

  def obsolete(:core_lib, :is_literal, 1) do
    {:removed, ~c"use cerl:is_literal/1 instead"}
  end

  def obsolete(:core_lib, :is_literal_list, 1) do
    {:removed, ~c"use cerl:is_literal_list/1 instead"}
  end

  def obsolete(:core_lib, :literal_value, 1) do
    {:removed, ~c"use cerl:concrete/1 instead"}
  end

  def obsolete(:core_lib, :set_anno, 2) do
    {:removed, ~c"use cerl:set_ann/2 instead"}
  end

  def obsolete(:crypto, :block_decrypt, 3) do
    {:removed,
     ~c"use crypto:crypto_one_time/4 or crypto:crypto_init/3 + crypto:crypto_update/2 + crypto:crypto_final/1 instead"}
  end

  def obsolete(:crypto, :block_decrypt, 4) do
    {:removed,
     ~c"use crypto:crypto_one_time/5, crypto:crypto_one_time_aead/6,7 or crypto:crypto_(dyn_iv)?_init + crypto:crypto_(dyn_iv)?_update + crypto:crypto_final instead"}
  end

  def obsolete(:crypto, :block_encrypt, 3) do
    {:removed,
     ~c"use crypto:crypto_one_time/4 or crypto:crypto_init/3 + crypto:crypto_update/2 + crypto:crypto_final/1 instead"}
  end

  def obsolete(:crypto, :block_encrypt, 4) do
    {:removed,
     ~c"use crypto:crypto_one_time/5, crypto:crypto_one_time_aead/6,7 or crypto:crypto_(dyn_iv)?_init + crypto:crypto_(dyn_iv)?_update + crypto:crypto_final instead"}
  end

  def obsolete(:crypto, :cmac, 3) do
    {:removed, ~c"use crypto:mac/4 instead"}
  end

  def obsolete(:crypto, :cmac, 4) do
    {:removed, ~c"use crypto:macN/5 instead"}
  end

  def obsolete(:crypto, :hmac, 3) do
    {:removed, ~c"use crypto:mac/4 instead"}
  end

  def obsolete(:crypto, :hmac, 4) do
    {:removed, ~c"use crypto:macN/5 instead"}
  end

  def obsolete(:crypto, :hmac_final, 1) do
    {:removed, ~c"use crypto:mac_final/1 instead"}
  end

  def obsolete(:crypto, :hmac_final_n, 2) do
    {:removed, ~c"use crypto:mac_finalN/2 instead"}
  end

  def obsolete(:crypto, :hmac_init, 2) do
    {:removed, ~c"use crypto:mac_init/3 instead"}
  end

  def obsolete(:crypto, :hmac_update, 2) do
    {:removed, ~c"use crypto:mac_update/2 instead"}
  end

  def obsolete(:crypto, :poly1305, 2) do
    {:removed, ~c"use crypto:mac/3 instead"}
  end

  def obsolete(:crypto, :stream_decrypt, 2) do
    {:removed, ~c"use crypto:crypto_update/2 instead"}
  end

  def obsolete(:crypto, :stream_encrypt, 2) do
    {:removed, ~c"use crypto:crypto_update/2 instead"}
  end

  def obsolete(:disk_log, :accessible_logs, 0) do
    {:removed, ~c"use disk_log:all/0 instead"}
  end

  def obsolete(:disk_log, :lclose, 1) do
    {:removed, ~c"use disk_log:close/1 instead"}
  end

  def obsolete(:disk_log, :lclose, 2) do
    {:removed, ~c"use disk_log:close/1 instead"}
  end

  def obsolete(:erl_lint, :modify_line, 2) do
    {:removed, ~c"use erl_parse:map_anno/2 instead"}
  end

  def obsolete(:erl_parse, :get_attribute, 2) do
    {:removed, ~c"erl_anno:{column,line,location,text}/1 instead"}
  end

  def obsolete(:erl_parse, :get_attributes, 1) do
    {:removed, ~c"erl_anno:{column,line,location,text}/1 instead"}
  end

  def obsolete(:erl_parse, :set_line, 2) do
    {:removed, ~c"use erl_anno:set_line/2"}
  end

  def obsolete(:erl_scan, :set_attribute, 3) do
    {:removed, ~c"use erl_anno:set_line/2 instead"}
  end

  def obsolete(:erlang, :get_stacktrace, 0) do
    {:removed, ~c"use the new try/catch syntax for retrieving the stack backtrace"}
  end

  def obsolete(:erlang, :hash, 2) do
    {:removed, ~c"use erlang:phash2/2 instead"}
  end

  def obsolete(:filename, :safe_relative_path, 1) do
    {:removed, ~c"use filelib:safe_relative_path/2 instead"}
  end

  def obsolete(:ftp, :start_service, 1) do
    {:removed, ~c"use ftp:open/2 instead"}
  end

  def obsolete(:ftp, :stop_service, 1) do
    {:removed, ~c"use ftp:close/1 instead"}
  end

  def obsolete(:http_uri, :parse, 1) do
    {:removed, ~c"use uri_string functions instead"}
  end

  def obsolete(:http_uri, :parse, 2) do
    {:removed, ~c"use uri_string functions instead"}
  end

  def obsolete(:http_uri, :scheme_defaults, 0) do
    {:removed, ~c"use uri_string functions instead"}
  end

  def obsolete(:httpd_conf, :check_enum, 2) do
    {:removed, ~c"use lists:member/2 instead"}
  end

  def obsolete(:httpd_conf, :clean, 1) do
    {:removed, ~c"use string:strip/1 instead or possibly the re module"}
  end

  def obsolete(:httpd_conf, :custom_clean, 3) do
    {:removed, ~c"use string:strip/1 instead or possibly the re module"}
  end

  def obsolete(:httpd_conf, :is_directory, 1) do
    {:removed, ~c"use filelib:is_dir/1 instead"}
  end

  def obsolete(:httpd_conf, :is_file, 1) do
    {:removed, ~c"use filelib:is_file/1 instead"}
  end

  def obsolete(:httpd_conf, :make_integer, 1) do
    {:removed, ~c"use erlang:list_to_integer/1 instead"}
  end

  def obsolete(:httpd_util, :decode_hex, 1) do
    {:removed, ~c"use uri_string:unquote function instead"}
  end

  def obsolete(:httpd_util, :encode_hex, 1) do
    {:removed, ~c"use uri_string:quote function instead"}
  end

  def obsolete(:httpd_util, :flatlength, 1) do
    {:removed, ~c"use erlang:iolist_size/1 instead"}
  end

  def obsolete(:httpd_util, :hexlist_to_integer, 1) do
    {:removed, ~c"use erlang:list_to_integer/2 with base 16 instead"}
  end

  def obsolete(:httpd_util, :integer_to_hexlist, 1) do
    {:removed, ~c"use erlang:integer_to_list/2 with base 16 instead"}
  end

  def obsolete(:httpd_util, :strip, 1) do
    {:removed, ~c"use string:trim/1 instead"}
  end

  def obsolete(:httpd_util, :suffix, 1) do
    {:removed, ~c"use filename:extension/1 and string:trim/2 instead"}
  end

  def obsolete(:net, :relay, 1) do
    {:removed, ~c"use fun Relay(Pid) -> receive X -> Pid ! X end, Relay(Pid) instead"}
  end

  def obsolete(:public_key, :ssh_decode, 2) do
    {:removed, ~c"use ssh_file:decode/2 instead"}
  end

  def obsolete(:public_key, :ssh_encode, 2) do
    {:removed, ~c"use ssh_file:encode/2 instead"}
  end

  def obsolete(:public_key, :ssh_hostkey_fingerprint, 1) do
    {:removed, ~c"use ssh:hostkey_fingerprint/1 instead"}
  end

  def obsolete(:public_key, :ssh_hostkey_fingerprint, 2) do
    {:removed, ~c"use ssh:hostkey_fingerprint/2 instead"}
  end

  def obsolete(:rpc, :safe_multi_server_call, 2) do
    {:removed, ~c"use rpc:multi_server_call/2 instead"}
  end

  def obsolete(:rpc, :safe_multi_server_call, 3) do
    {:removed, ~c"use rpc:multi_server_call/3 instead"}
  end

  def obsolete(:ssl, :cipher_suites, 0) do
    {:removed, ~c"use cipher_suites/2,3 instead"}
  end

  def obsolete(:ssl, :cipher_suites, 1) do
    {:removed, ~c"use cipher_suites/2,3 instead"}
  end

  def obsolete(:ssl, :connection_info, 1) do
    {:removed, ~c"use ssl:connection_information/[1,2] instead"}
  end

  def obsolete(:ssl, :negotiated_next_protocol, 1) do
    {:removed, ~c"use ssl:negotiated_protocol/1 instead"}
  end

  def obsolete(:auth, :node_cookie, _) do
    {:deprecated, ~c"use erlang:set_cookie/2 and net_adm:ping/1 instead"}
  end

  def obsolete(:asn1ct, :decode, _) do
    {:removed, ~c"use Mod:decode/2 instead"}
  end

  def obsolete(:asn1ct, :encode, _) do
    {:removed, ~c"use Mod:encode/2 instead"}
  end

  def obsolete(:crypto, :next_iv, _) do
    {:removed, ~c"see the 'New and Old API' chapter of the CRYPTO User's guide"}
  end

  def obsolete(:crypto, :stream_init, _) do
    {:removed,
     ~c"use crypto:crypto_init/3 + crypto:crypto_update/2 + crypto:crypto_final/1 or crypto:crypto_one_time/4 instead"}
  end

  def obsolete(:erl_scan, :attributes_info, _) do
    {:removed, ~c"use erl_anno:{column,line,location,text}/1 instead"}
  end

  def obsolete(:erl_scan, :token_info, _) do
    {:removed, ~c"use erl_scan:{category,column,line,location,symbol,text}/1 instead"}
  end

  def obsolete(:filename, :find_src, _) do
    {:removed, ~c"use filelib:find_source/1,3 instead"}
  end

  def obsolete(:ssl, :ssl_accept, _) do
    {:removed, ~c"use ssl_handshake/1,2,3 instead"}
  end

  def obsolete(:ct_slave, _, _) do
    {:deprecated, ~c"use ?CT_PEER(), or the 'peer' module instead", ~c"OTP 29"}
  end

  def obsolete(:gen_fsm, _, _) do
    {:deprecated, ~c"use the 'gen_statem' module instead"}
  end

  def obsolete(:random, _, _) do
    {:deprecated, ~c"use the 'rand' module instead"}
  end

  def obsolete(:slave, _, _) do
    {:deprecated, ~c"use the 'peer' module instead", ~c"OTP 29"}
  end

  def obsolete(:erts_alloc_config, _, _) do
    {:removed, ~c"this module has as of OTP 26.0 been removed"}
  end

  def obsolete(:os_mon_mib, _, _) do
    {:removed, ~c"this module was removed in OTP 22.0"}
  end

  def obsolete(:pg2, _, _) do
    {:removed, ~c"this module was removed in OTP 24. Use 'pg' instead"}
  end

  def obsolete(_, _, _) do
    :no
  end

  def obsolete_type(:crypto, :hmac_state, 0) do
    {:removed, ~c"see the 'New and Old API' chapter of the CRYPTO User's guide"}
  end

  def obsolete_type(:crypto, :retired_cbc_cipher_aliases, 0) do
    {:removed, ~c"Use aes_*_cbc or des_ede3_cbc"}
  end

  def obsolete_type(:crypto, :retired_cfb_cipher_aliases, 0) do
    {:removed, ~c"Use aes_*_cfb8, aes_*_cfb128 or des_ede3_cfb"}
  end

  def obsolete_type(:crypto, :retired_ctr_cipher_aliases, 0) do
    {:removed, ~c"Use aes_*_ctr"}
  end

  def obsolete_type(:crypto, :retired_ecb_cipher_aliases, 0) do
    {:removed, ~c"Use aes_*_ecb"}
  end

  def obsolete_type(:crypto, :stream_state, 0) do
    {:removed, ~c"see the 'New and Old API' chapter of the CRYPTO User's guide"}
  end

  def obsolete_type(:erl_scan, :column, 0) do
    {:removed, ~c"use erl_anno:column() instead"}
  end

  def obsolete_type(:erl_scan, :line, 0) do
    {:removed, ~c"use erl_anno:line() instead"}
  end

  def obsolete_type(:erl_scan, :location, 0) do
    {:removed, ~c"use erl_anno:location() instead"}
  end

  def obsolete_type(:http_uri, :default_scheme_port_number, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :fragment, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :host, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :path, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :query, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :scheme, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :uri, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(:http_uri, :user_info, 0) do
    {:removed, ~c"use uri_string instead"}
  end

  def obsolete_type(_, _, _) do
    :no
  end
end
