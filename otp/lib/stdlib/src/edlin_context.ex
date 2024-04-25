defmodule :m_edlin_context do
  use Bitwise
  require Record
  Record.defrecord(:r_context, :context, arguments: [],
                                   fields: [], parameter_count: 0,
                                   current_field: [], nestings: [])
  def get_context(line) do
    {bef0, word} = :edlin_expand.over_word(line)
    case ({{bef0, word}, odd_quotes(?", bef0)}) do
      {_, true} ->
        {:string}
      {{[?# | _], []}, _} ->
        {:map_or_record}
      {{_Bef1, ^word}, _} ->
        case (is_binding(word)) do
          true ->
            {:binding}
          false ->
            get_context(bef0, word)
        end
    end
  end

  def get_context('>-' ++ _, l) when is_list(l) do
    {:term}
  end

  def get_context([?? | _], _) do
    {:macro}
  end

  def get_context(bef0, word) when is_list(word) do
    get_context(:lists.reverse(word) ++ bef0, r_context())
  end

  def get_context([],
           r_context(arguments: args, parameter_count: count,
               nestings: nestings) = _CR) do
    case (count + 1 == length(args) and nestings === []) do
      true ->
        {:term, :lists.droplast(args), :lists.last(args)}
      _ ->
        nestings1 = :lists.reverse(nestings)
        case (nestings1) do
          [] ->
            case (count) do
              0 when length(args) > 0 ->
                {:term, :lists.droplast(args), :lists.last(args)}
              _ ->
                {:term, args, []}
            end
          [{:list, args1, arg} | _] ->
            {:term, args1, arg}
          [{:tuple, args1, arg} | _] ->
            {:term, args1, arg}
          [{:map, _Fields, _FieldToComplete, args1, arg} | _] ->
            {:term, args1, arg}
        end
    end
  end

  def get_context([?( | bef], cR) do
    {bef1, fun} = :edlin_expand.over_word(bef)
    case (fun) do
      [] ->
        {:term}
      _ ->
        {_, mod} = over_module(bef1, fun)
        case (mod) do
          'shell' ->
            {:term}
          'shell_default' ->
            {:term}
          _ ->
            case (r_context(cR, :parameter_count) + 1 == length(r_context(cR, :arguments))) do
              true ->
                {:function, mod, fun,
                   :lists.droplast(r_context(cR, :arguments)),
                   :lists.last(r_context(cR, :arguments)), r_context(cR, :nestings)}
              _ ->
                {:function, mod, fun, r_context(cR, :arguments), [],
                   r_context(cR, :nestings)}
            end
        end
    end
  end

  def get_context([?{ | bef],
           r_context(fields: fields, current_field: fieldToComplete,
               arguments: arguments, parameter_count: count,
               nestings: nestings)) do
    {args,
       unfinished} = (case (count + 1 == length(arguments)) do
                        true ->
                          {:lists.droplast(arguments), :lists.last(arguments)}
                        _ ->
                          {arguments, []}
                      end)
    case (:edlin_expand.over_word(bef)) do
      {[?# | bef1], []} ->
        {bef2, map} = :edlin_expand.over_word(bef1)
        case (map) do
          [] ->
            get_context(bef2,
                          r_context(nestings: [{:map, fields, fieldToComplete, args,
                                          unfinished} |
                                           nestings]))
          _ ->
            {:map, map, fields}
        end
      {_, []} ->
        get_context(bef,
                      r_context(nestings: [{:tuple, args, unfinished} | nestings]))
      {[?# | _Bef3], record} ->
        {:record, record, fields, fieldToComplete, args,
           unfinished, nestings}
      {[], _} ->
        get_context(bef,
                      r_context(nestings: [{:tuple, args, unfinished} | nestings]))
      {_, _} ->
        get_context(bef,
                      r_context(nestings: [{:tuple, args, unfinished} | nestings]))
    end
  end

  def get_context([?[ | bef1],
           r_context(arguments: arguments, parameter_count: count,
               nestings: nestings)) do
    {args,
       unfinished} = (case (count + 1 == length(arguments)) do
                        true ->
                          {:lists.droplast(arguments), :lists.last(arguments)}
                        _ ->
                          {arguments, []}
                      end)
    get_context(bef1,
                  r_context(nestings: [{:list, args, unfinished} | nestings]))
  end

  def get_context([?, | bef1], r_context(parameter_count: count) = cR) do
    get_context(bef1, r_context(cR, parameter_count: count + 1))
  end

  def get_context([?>, ?= | bef1],
           r_context(parameter_count: count, fields: fields) = cR) do
    {bef2, field} = :edlin_expand.over_word(bef1)
    case (count) do
      0 ->
        get_context(bef2,
                      r_context(cR, fields: [field | fields],  current_field: field))
      _ ->
        get_context(bef2, r_context(cR, fields: [field | fields]))
    end
  end

  def get_context([?=, ?: | bef1],
           r_context(parameter_count: count, fields: fields) = cR) do
    {bef2, field} = :edlin_expand.over_word(bef1)
    case (count) do
      0 ->
        get_context(bef2,
                      r_context(cR, fields: [field | fields],  current_field: field))
      _ ->
        get_context(bef2, r_context(cR, fields: [field | fields]))
    end
  end

  def get_context([?= | bef1],
           r_context(parameter_count: count, fields: fields) = cR) do
    {bef2, field} = :edlin_expand.over_word(bef1)
    case (count) do
      0 ->
        get_context(bef2,
                      r_context(cR, fields: [field | fields],  current_field: field))
      _ ->
        get_context(bef2, r_context(cR, fields: [field | fields]))
    end
  end

  def get_context([?. | bef2], cR) do
    arguments = r_context(cR, :arguments)
    count = r_context(cR, :parameter_count)
    {args,
       unfinished} = (case (count + 1 == length(arguments)) do
                        true ->
                          {:lists.droplast(arguments), :lists.last(arguments)}
                        _ ->
                          {arguments, []}
                      end)
    case (:edlin_expand.over_word(bef2)) do
      {[?# | _Bef3], record} ->
        {:record, record, r_context(cR, :fields), r_context(cR, :current_field),
           args, unfinished, r_context(cR, :nestings)}
      _ ->
        {:end}
    end
  end

  def get_context([?: | bef2], _) do
    {bef3, mod} = :edlin_expand.over_word(bef2)
    case (:edlin_expand.over_word(bef3)) do
      {_, 'fun'} ->
        {:fun_, mod}
      _ ->
        {:function}
    end
  end

  def get_context([?/ | bef1], _) do
    {bef2, fun} = :edlin_expand.over_word(bef1)
    {_, mod} = over_module(bef2, fun)
    {:fun_, mod, fun}
  end

  def get_context([?>, ?- | _Bef2], r_context(arguments: args) = cR) do
    case (r_context(cR, :parameter_count) + 1 == length(args)) do
      true ->
        {:term, :lists.droplast(args), :lists.last(args)}
      _ ->
        {:term, args, []}
    end
  end

  def get_context('nehw ' ++ _Bef2, r_context(arguments: args) = cR) do
    case (r_context(cR, :parameter_count) + 1 == length(args)) do
      true ->
        {:term, :lists.droplast(args), :lists.last(args)}
      _ ->
        {:term, args, []}
    end
  end

  def get_context([?\s | bef], cR) do
    get_context(bef, cR)
  end

  def get_context(bef0,
           r_context(arguments: args, parameter_count: count) = cR) do
    case (over_to_opening(bef0)) do
      {_, []} ->
        {:term}
      {:error, _} = e ->
        e
      {:record} ->
        {:record}
      {:fun_} ->
        {:fun_}
      {:new_fun, _} = f ->
        f
      {bef1, {:fun_, str} = arg} ->
        case (count) do
          0 ->
            [_, mod, fun | _] = :string.tokens(str, ' :/')
            {:fun_, mod, fun}
          _ ->
            get_context(bef1, r_context(cR, arguments: [arg | args]))
        end
      {bef1, arg} ->
        get_context(bef1, r_context(cR, arguments: [arg | args]))
    end
  end

  defp read_operator(bef) do
    read_operator1(bef)
  end

  defp operator_string() do
    '-=><:+*/|&^~'
  end

  defp read_operator1([?\s | bef]) do
    read_operator1(bef)
  end

  defp read_operator1('mer ' ++ bef) do
    {bef, 'rem'}
  end

  defp read_operator1('osladna ' ++ bef) do
    {bef, 'andalso'}
  end

  defp read_operator1('dna ' ++ bef) do
    {bef, 'and'}
  end

  defp read_operator1('eslero ' ++ bef) do
    {bef, 'orelse'}
  end

  defp read_operator1('ro ' ++ bef) do
    {bef, 'or'}
  end

  defp read_operator1([?>, ?>, ?> | bef1]) do
    {[?>, ?> | bef1], [?>]}
  end

  defp read_operator1([?>, ?> | bef1]) do
    {[?> | bef1], [?>]}
  end

  defp read_operator1([?>, ?-, c | bef1] = bef) do
    case (:lists.member(c, operator_string())) do
      true ->
        {bef1, [c, ?-, ?>]}
      false ->
        {bef, []}
    end
  end

  defp read_operator1([?>, ?=, c | bef1] = bef) do
    case (:lists.member(c, operator_string())) do
      true ->
        {bef1, [c, ?=, ?>]}
      false ->
        {bef, []}
    end
  end

  defp read_operator1([?=, ?:, c | bef1] = bef) do
    case (:lists.member(c, operator_string())) do
      true ->
        {bef1, [c, ?:, ?=]}
      false ->
        {bef, []}
    end
  end

  defp read_operator1([?: | _] = bef) do
    {bef, []}
  end

  defp read_operator1([op1, op2, op3 | bef]) do
    case ({:lists.member(op1, operator_string()),
             :lists.member(op2, operator_string()),
             :lists.member(op3, operator_string())}) do
      {true, true, true} ->
        {bef, [op3, op2, op1]}
      {true, true, false} ->
        {[op3 | bef], [op2, op1]}
      {true, false, _} ->
        {[op2, op3 | bef], [op1]}
      _ ->
        {[op1, op2, op3 | bef], []}
    end
  end

  defp read_operator1([op1, op2]) do
    case ({:lists.member(op1, operator_string()),
             :lists.member(op2, operator_string())}) do
      {true, true} ->
        {[], [op2, op1]}
      {true, false} ->
        {[op2], [op1]}
      _ ->
        {[op1, op2], []}
    end
  end

  defp read_operator1([op1]) do
    case (:lists.member(op1, operator_string())) do
      true ->
        {[], [op1]}
      _ ->
        {[op1], []}
    end
  end

  defp read_operator1(bef) do
    {bef, []}
  end

  defp read_opening_char('nehw ' ++ bef) do
    {bef, 'when'}
  end

  defp read_opening_char([oC | bef]) when oC === ?( or oC === ?[ or
                             oC === ?{ or oC === ?, or oC === ?. do
    {bef, [oC]}
  end

  defp read_opening_char([?>, ?- | _] = bef) do
    case (read_operator(bef)) do
      {_, []} ->
        {bef, '->'}
      _ ->
        {bef, []}
    end
  end

  defp read_opening_char([?\s | bef]) do
    read_opening_char(bef)
  end

  defp read_opening_char(bef) do
    {bef, []}
  end

  defp over_to_opening(bef) do
    try do
      over_to_opening1(bef, %{args: []})
    catch
      e ->
        e
    end
  end

  defp over_to_opening1([], %{args: args}) do
    over_to_opening_return([], args)
  end

  defp over_to_opening1(bef, acc = %{args: args}) do
    case (:edlin_expand.over_word(bef)) do
      {_, []} ->
        case (read_opening_char(bef)) do
          {bef1, []} ->
            case (extract_argument2(bef1)) do
              {:stop} ->
                over_to_opening_return(bef1, args)
              {bef2, []} ->
                over_to_opening_return(bef2, args)
              {bef2, arg} ->
                over_to_opening1(bef2,
                                   Map.put(acc, :args, [arg | args]))
            end
          {_Bef1, _Opening} ->
            over_to_opening_return(bef, args)
        end
      _ ->
        case (extract_argument2(bef)) do
          {:stop} ->
            over_to_opening_return(bef, args)
          {bef2, []} ->
            over_to_opening_return(bef2, args)
          {bef2, arg} ->
            over_to_opening1(bef2,
                               Map.put(acc, :args, [arg | args]))
        end
    end
  end

  defp over_to_opening_return(bef, args) do
    case (args) do
      [] ->
        {bef, []}
      [arg] ->
        {bef, arg}
      [{:operator, '-'}, {:integer, i}] ->
        {bef, {:integer, '-' ++ i}}
      [{:operator, '-'}, {:float, f}] ->
        {bef, {:float, '-' ++ f}}
      [{:atom, 'fun'}, {:atom, _}] ->
        throw({:fun_})
      _ ->
        case (look_for_non_operator_separator(args)) do
          true ->
            {bef,
               {:operation,
                  :lists.flatten(:lists.join(' ',
                                               :lists.map(fn {_, arg} ->
                                                               arg
                                                          end,
                                                            args)))}}
          false ->
            {:error, length(bef)}
        end
    end
  end

  defp look_for_non_operator_separator([{:string, _}, {:string, _} = a | args]) do
    look_for_non_operator_separator([a | args])
  end

  defp look_for_non_operator_separator([{:operator, _}, {:operator, _} | _]) do
    false
  end

  defp look_for_non_operator_separator([_, {:operator, _} = b | args]) do
    look_for_non_operator_separator([b | args])
  end

  defp look_for_non_operator_separator([{:operator, _}, b | args]) do
    look_for_non_operator_separator([b | args])
  end

  defp look_for_non_operator_separator([_]) do
    true
  end

  defp look_for_non_operator_separator(_) do
    false
  end

  defp over_map_record_or_tuple(bef0) do
    case (over_to_opening_paren(?}, bef0)) do
      {_, []} ->
        throw({:error, length(bef0)})
      {bef3, clause} ->
        {bef4, maybeRecord} = :edlin_expand.over_word(bef3)
        case (maybeRecord) do
          [] ->
            case (bef4) do
              [?# | bef5] ->
                {bef6, _Var} = :edlin_expand.over_word(bef5)
                {bef6, {:map, _Var ++ '#' ++ clause}}
              _ ->
                {bef4, {:tuple, clause}}
            end
          _Record ->
            [?# | bef5] = bef4
            {bef6, _Var} = :edlin_expand.over_word(bef5)
            {bef6, {:record, _Var ++ '#' ++ _Record ++ clause}}
        end
    end
  end

  defp over_pid_port_or_ref(bef2) do
    case (over_to_opening_paren(?>, bef2)) do
      {_, []} ->
        throw({:soft_error, length(bef2)})
      {bef3, clause} ->
        case (bef3) do
          'feR#' ++ bef4 ->
            {bef4, {:ref, '#Ref' ++ clause}}
          'nuF#' ++ bef4 ->
            {bef4, {:funref, '#Fun' ++ clause}}
          'troP#' ++ bef4 ->
            {bef4, {:port, '#Port' ++ clause}}
          _ ->
            case (:edlin_expand.over_word(bef3)) do
              {^bef3, []} ->
                case (bef2) do
                  [?> | _] ->
                    {bef3, {:binary, clause}}
                  _ ->
                    {bef3, {:pid, clause}}
                end
              _ ->
                throw({:error, length(bef3)})
            end
        end
    end
  end

  defp over_list(bef2) do
    case (over_to_opening_paren(?], bef2)) do
      {_, []} ->
        throw({:error, length(bef2)})
      {bef3, clause} ->
        {bef3, {:list, clause}}
    end
  end

  defp over_parenthesis_or_call(bef2) do
    case (over_to_opening_paren(?), bef2)) do
      {_, []} ->
        throw({:error, length(bef2)})
      {bef3, clause} ->
        {bef4, fun} = :edlin_expand.over_word(bef3)
        {bef5, modFun} = (case (bef4) do
                            [?: | bef41] ->
                              {bef42, mod} = :edlin_expand.over_word(bef41)
                              {bef42, mod ++ [?: | fun]}
                            _ ->
                              {bef4, fun}
                          end)
        case (modFun) do
          [] ->
            {bef5, {:parenthesis, clause}}
          'fun' ->
            throw({:new_fun, clause})
          _ ->
            {bef5, {:call, modFun ++ clause}}
        end
    end
  end

  defp over_keyword_or_fun(bef1) do
    case (over_keyword_expression(bef1)) do
      {bef2, keywordExpression} ->
        {bef2, {:keyword, keywordExpression ++ ' end'}}
      _ ->
        throw({:error, length(bef1)})
    end
  end

  defp extract_argument2([?> | bef0] = bef) do
    case (read_operator(bef)) do
      {[?> | _] = bef1, '>' = operator} ->
        try do
          over_pid_port_or_ref(bef0)
        catch
          {:error, _} = e ->
            throw(e)
          {:soft_error, _Col} ->
            {bef1, {:operator, operator}}
        end
      {bef1, '>' = operator} ->
        try do
          over_pid_port_or_ref(bef1)
        catch
          {:error, _} = e ->
            throw(e)
          {:soft_error, _Col} ->
            {bef1, {:operator, operator}}
        end
      {_Bef1, []} ->
        {:stop}
      {bef1, operator} ->
        {bef1, {:operator, operator}}
    end
  end

  defp extract_argument2(bef0) do
    case (read_operator(bef0)) do
      {[?} | bef1], []} ->
        over_map_record_or_tuple(bef1)
      {[?) | bef1], []} ->
        over_parenthesis_or_call(bef1)
      {[?] | bef1], []} ->
        over_list(bef1)
      {[?" | bef2], []} ->
        {bef3, _Quote} = over_to_opening_quote(?", bef2)
        {bef3, {:string, _Quote}}
      {'dne ' ++ bef1, []} ->
        over_keyword_or_fun(bef1)
      {[?=, ?: | _], []} ->
        {:stop}
      {[?: | _], []} ->
        {:stop}
      {'nehw' ++ _Bef1, []} ->
        {:stop}
      {_, []} ->
        extract_argument(bef0)
      {bef1, operator} ->
        {bef1, {:operator, operator}}
    end
  end

  defp extract_argument(bef0) do
    case (:edlin_expand.over_word(bef0)) do
      {_Bef1, []} ->
        case (read_char(_Bef1)) do
          {_, []} ->
            {_Bef1, []}
          {bef2, char} ->
            {bef2, {:char, char}}
        end
      {bef2, var} ->
        try do
          :erlang.list_to_integer(var)
        catch
          _, _ ->
            case (is_binding(var)) do
              true ->
                {bef2, {:var, var}}
              false ->
                case (bef2) do
                  [?# | _] ->
                    throw({:record})
                  _ ->
                    {bef2, {:atom, var}}
                end
            end
        else
          _ ->
            case (over_fun_function(bef0)) do
              {bef3, 'fun ' ++ _ModFunArr} ->
                {bef3, {:fun_, 'fun ' ++ _ModFunArr}}
              _ ->
                case (over_number(bef0)) do
                  {bef3, []} ->
                    {bef3, []}
                  {bef3, number} ->
                    {bef3, number}
                end
            end
        end
    end
  end

  defp over_number(bef) do
    case (:edlin_expand.over_word(bef)) do
      {_, []} ->
        {bef, []}
      {bef2, var} ->
        try do
          :erlang.list_to_integer(var)
        catch
          _, _ ->
            {bef, []}
        else
          _ ->
            {bef6,
               {numberType,
                  number}} = (res = (case (:edlin_expand.over_word(bef2)) do
                                       {[?. | bef3], []} ->
                                         {bef4,
                                            integer} = :edlin_expand.over_word(bef3)
                                         {bef4, {:float, integer ++ '.' ++ var}}
                                       {[?# | bef3], []} ->
                                         {bef4,
                                            base} = :edlin_expand.over_word(bef3)
                                         {bef4, {:integer, base ++ '#' ++ var}}
                                       _ ->
                                         {bef2, {:integer, var}}
                                     end))
            case (:edlin_expand.over_word(bef6)) do
              {[?- | bef5], []} ->
                case (read_opening_char(bef5)) do
                  {_, []} ->
                    res
                  _ ->
                    {bef5, {numberType, '-' ++ number}}
                end
              _ ->
                res
            end
        end
    end
  end

  defp read_char([c, ?$ | line]) do
    {line, [?$, c]}
  end

  defp read_char([?$ | line]) do
    {line, '$ '}
  end

  defp read_char(line) do
    {line, []}
  end

  defp over_fun_function(bef) do
    over_fun_function(bef, [])
  end

  defp over_fun_function(bef, acc) do
    case (:edlin_expand.over_word(bef)) do
      {[?/ | bef1], arity} ->
        over_fun_function(bef1, [?/ | arity] ++ acc)
      {[?: | bef1], fun} ->
        over_fun_function(bef1, [?: | fun] ++ acc)
      {' nuf' ++ bef1, modOrFun} ->
        case (to_atom(modOrFun)) do
          {:ok, _} ->
            over_fun_function(bef1, 'fun ' ++ modOrFun ++ acc)
          :error ->
            {bef, acc}
        end
      _ ->
        {bef, acc}
    end
  end

  defp over_to_opening_quote(q, bef) when q == ?' or q == ?" do
    over_to_opening_quote([q], bef, [q])
  end

  defp over_to_opening_quote(_, bef) do
    {bef, []}
  end

  defp over_to_opening_quote([], bef, word) do
    {bef, word}
  end

  defp over_to_opening_quote([q | stack], [q | bef], word) do
    over_to_opening_quote(stack, bef, [q | word])
  end

  defp over_to_opening_quote([q | stack], [q, eC | bef], word)
      when eC === ?\\ or eC === ?$ do
    over_to_opening_quote([q | stack], bef, [eC, q | word])
  end

  defp over_to_opening_quote([stack], [c | bef], word) do
    over_to_opening_quote([stack], bef, [c | word])
  end

  defp over_to_opening_quote(_, _, word) do
    {:lists.reverse(word), []}
  end

  defp matching_paren(?(, ?)) do
    true
  end

  defp matching_paren(?[, ?]) do
    true
  end

  defp matching_paren(?{, ?}) do
    true
  end

  defp matching_paren(?<, ?>) do
    true
  end

  defp matching_paren(_, _) do
    false
  end

  defp over_to_opening_paren(cC, bef) when cC == ?) or cC == ?] or
                          cC == ?} or cC == ?> do
    over_to_opening_paren([cC], bef, [cC])
  end

  defp over_to_opening_paren(_, bef) do
    {bef, []}
  end

  defp over_to_opening_paren([], bef, word) do
    {bef, word}
  end

  defp over_to_opening_paren(_, [], word) do
    {:lists.reverse(word), []}
  end

  defp over_to_opening_paren([cC | stack], [cC, ?$ | bef], word) do
    over_to_opening_paren([cC | stack], bef,
                            [?$, cC | word])
  end

  defp over_to_opening_paren([cC | stack], [oC | bef], word) when oC == ?( or
                                                 oC == ?[ or oC == ?{ or
                                                 oC == ?< do
    case (matching_paren(oC, cC)) do
      true ->
        over_to_opening_paren(stack, bef, [oC | word])
      false ->
        over_to_opening_paren([cC | stack], bef, [oC | word])
    end
  end

  defp over_to_opening_paren([cC | stack], [cC | bef], word) do
    over_to_opening_paren([cC, cC | stack], bef,
                            [cC | word])
  end

  defp over_to_opening_paren(stack, [q, nEC | bef], word) when q == ?" or
                                              (q == ?' and nEC != ?$ and
                                                 nEC != ?\\) do
    {bef1, quotedWord} = over_to_opening_quote(q, bef)
    over_to_opening_paren(stack, bef1, quotedWord ++ word)
  end

  defp over_to_opening_paren(cC, [c | bef], word) do
    over_to_opening_paren(cC, bef, [c | word])
  end

  defp over_keyword_expression(bef) do
    over_keyword_expression(bef, [])
  end

  defp over_keyword_expression('dne' ++ bef, expr) do
    {bef1, kWE} = over_keyword_expression(bef)
    over_keyword_expression(bef1, kWE ++ 'end' ++ expr)
  end

  defp over_keyword_expression('fi' ++ bef, expr) do
    {bef, 'if' ++ expr}
  end

  defp over_keyword_expression('nuf' ++ bef, expr) do
    {bef, 'fun' ++ expr}
  end

  defp over_keyword_expression('yrt' ++ bef, expr) do
    {bef, 'try' ++ expr}
  end

  defp over_keyword_expression('esac' ++ bef, expr) do
    {bef, 'case' ++ expr}
  end

  defp over_keyword_expression('hctac' ++ bef, expr) do
    case (over_keyword_expression(bef, [])) do
      {bef1, 'try' ++ expr1} ->
        {bef1, 'try' ++ expr1 ++ 'catch' ++ expr}
      _ ->
        {bef, 'catch' ++ expr}
    end
  end

  defp over_keyword_expression('nigeb' ++ bef, expr) do
    {bef, 'begin' ++ expr}
  end

  defp over_keyword_expression('ebyam' ++ bef, expr) do
    {bef, 'maybe' ++ expr}
  end

  defp over_keyword_expression('eviecer' ++ bef, expr) do
    {bef, 'receive' ++ expr}
  end

  defp over_keyword_expression([], _) do
    {:no, [], []}
  end

  defp over_keyword_expression([c | bef], expr) do
    over_keyword_expression(bef, [c | expr])
  end

  defp odd_quotes(q, [q, c | line], acc) when c == ?\\ or
                                        c == ?$ do
    odd_quotes(q, line, acc)
  end

  defp odd_quotes(q, [q | line], acc) do
    odd_quotes(q, line, acc + 1)
  end

  defp odd_quotes(q, [_ | line], acc) do
    odd_quotes(q, line, acc)
  end

  defp odd_quotes(_, [], acc) do
    acc &&& 1 == 1
  end

  def odd_quotes(q, line) do
    odd_quotes(q, line, 0)
  end

  defp over_module(bef, fun) do
    case (:edlin_expand.over_word(bef)) do
      {[?: | bef1], _} ->
        :edlin_expand.over_word(bef1)
      {[], _} ->
        {bef, :edlin_expand.shell_default_or_bif(fun)}
      _ ->
        {bef, :edlin_expand.bif(fun)}
    end
  end

  defp is_binding(word) do
    normalized = :unicode.characters_to_nfc_list(word)
    :nomatch !== :re.run(normalized, '^[_[:upper:]][[:alpha:]]*$', [:unicode, :ucp])
  end

  defp to_atom(str) do
    case (:erl_scan.string(str)) do
      {:ok, [{:atom, _, a}], _} ->
        {:ok, a}
      _ ->
        :error
    end
  end

end