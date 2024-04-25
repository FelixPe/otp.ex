defmodule :m_eunit_tests do
  use Bitwise
  defp id(x) do
    x
  end

  defp under_eunit_test() do
    (
      (fn () ->
            x__T = :erlang.is_process_alive(self())
            case ((
                    case (:erlang.process_info(:erlang.group_leader(),
                                                 :current_function)) do
                      {:current_function, {:eunit_proc, _, _}} ->
                        true
                      _ ->
                        false
                    end
                  )) do
              ^x__T ->
                :ok
              x__V ->
                :erlang.error({:assert,
                                 [{:module, :eunit_tests}, {:line, 37},
                                                               {:expression, '? UNDER_EUNIT'},
                                                                   {:expected,
                                                                      true},
                                                                       case (not
                                                                             x__T) do
                                                                         ^x__V ->
                                                                           {:value,
                                                                              false}
                                                                         _ ->
                                                                           {:not_boolean,
                                                                              x__V}
                                                                       end]})
            end
       end).()
    )
  end

  defp let_test() do
    (
      (fn () ->
            x__X = 42
            case ((
                    (fn x ->
                          x + 25
                     end).(17)
                  )) do
              ^x__X ->
                :ok
              x__V ->
                :erlang.error({:assertEqual,
                                 [{:module, :eunit_tests}, {:line, 39},
                                                               {:expression, '? LET ( X , 17 , X + 25 )'},
                                                                   {:expected,
                                                                      x__X},
                                                                       {:value,
                                                                          x__V}]})
            end
       end).()
    )
  end

  defp if_test_() do
    [{42,
        fn () ->
             (
               (fn () ->
                     x__X = 17
                     case ((
                             case (id(1) > 0) do
                               true ->
                                 17
                               false ->
                                 42
                             end
                           )) do
                       ^x__X ->
                         :ok
                       x__V ->
                         :erlang.error({:assertEqual,
                                          [{:module, :eunit_tests}, {:line, 42},
                                                                        {:expression,
                                                                           '? IF ( id ( 1 ) > 0 , 17 , 42 )'},
                                                                            {:expected,
                                                                               x__X},
                                                                                {:value,
                                                                                   x__V}]})
                     end
                end).()
             )
        end},
         {43,
            fn () ->
                 (
                   (fn () ->
                         x__X = 42
                         case ((
                                 case (id(1) < 0) do
                                   true ->
                                     17
                                   false ->
                                     42
                                 end
                               )) do
                           ^x__X ->
                             :ok
                           x__V ->
                             :erlang.error({:assertEqual,
                                              [{:module, :eunit_tests}, {:line,
                                                                           43},
                                                                            {:expression,
                                                                               '? IF ( id ( 1 ) < 0 , 17 , 42 )'},
                                                                                {:expected,
                                                                                   x__X},
                                                                                    {:value,
                                                                                       x__V}]})
                         end
                    end).()
                 )
            end}]
  end

  defp matches_test_() do
    [{46,
        fn () ->
             (
               (fn () ->
                     x__T = :erlang.is_process_alive(self())
                     case ((
                             case ('hello') do
                               'hel' ++ _ ->
                                 true
                               _ ->
                                 false
                             end
                           )) do
                       ^x__T ->
                         :ok
                       x__V ->
                         :erlang.error({:assert,
                                          [{:module, :eunit_tests}, {:line, 46},
                                                                        {:expression,
                                                                           '? MATCHES ( "hel" ++ _ , "hello" )'},
                                                                            {:expected,
                                                                               true},
                                                                                case (not
                                                                                      x__T) do
                                                                                  ^x__V ->
                                                                                    {:value,
                                                                                       false}
                                                                                  _ ->
                                                                                    {:not_boolean,
                                                                                       x__V}
                                                                                end]})
                     end
                end).()
             )
        end},
         {47,
            fn () ->
                 (
                   (fn () ->
                         x__T = :erlang.is_process_alive(self())
                         case (not
                               (
                                 case ('hello') do
                                   'hal' ++ _ ->
                                     true
                                   _ ->
                                     false
                                 end
                               )) do
                           ^x__T ->
                             :ok
                           x__V ->
                             :erlang.error({:assert,
                                              [{:module, :eunit_tests}, {:line,
                                                                           47},
                                                                            {:expression,
                                                                               'not ( ? MATCHES ( "hal" ++ _ , "hello" ) )'},
                                                                                {:expected,
                                                                                   true},
                                                                                    case (not
                                                                                          x__T) do
                                                                                      ^x__V ->
                                                                                        {:value,
                                                                                           false}
                                                                                      _ ->
                                                                                        {:not_boolean,
                                                                                           x__V}
                                                                                    end]})
                         end
                    end).()
                 )
            end}]
  end

  defp get_output_test() do
    :io.format("Hello ~p!~n", [:eunit])
    (
      (fn () ->
            x__X = 'Hello eunit!\n'
            case (case ((
                          case (:erlang.process_info(:erlang.group_leader(),
                                                       :current_function)) do
                            {:current_function, {:eunit_proc, _, _}} ->
                              true
                            _ ->
                              false
                          end
                        )) do
                    true ->
                      :eunit_proc.get_output()
                    false ->
                      ''
                  end) do
              ^x__X ->
                :ok
              x__V ->
                :erlang.error({:assertEqual,
                                 [{:module, :eunit_tests}, {:line, 51},
                                                               {:expression, '? capturedOutput'},
                                                                   {:expected,
                                                                      x__X},
                                                                       {:value,
                                                                          x__V}]})
            end
       end).()
    )
    :io.format('System working?~n~s~n', ['Seems to be.'])
    (
      (fn () ->
            x__X = 'Hello eunit!\nSystem working?\nSeems to be.\n'
            case (case ((
                          case (:erlang.process_info(:erlang.group_leader(),
                                                       :current_function)) do
                            {:current_function, {:eunit_proc, _, _}} ->
                              true
                            _ ->
                              false
                          end
                        )) do
                    true ->
                      :eunit_proc.get_output()
                    false ->
                      ''
                  end) do
              ^x__X ->
                :ok
              x__V ->
                :erlang.error({:assertEqual,
                                 [{:module, :eunit_tests}, {:line, 54},
                                                               {:expression, '? capturedOutput'},
                                                                   {:expected,
                                                                      x__X},
                                                                       {:value,
                                                                          x__V}]})
            end
       end).()
    )
  end

end