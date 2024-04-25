defmodule :m_beam_call_types do
  use Bitwise
  import :lists, only: [any: 2, duplicate: 2, foldl: 3]
  require Record
  Record.defrecord(:r_t_atom, :t_atom, elements: :any)

  Record.defrecord(:r_t_bitstring, :t_bitstring,
    size_unit: 1,
    appendable: false
  )

  Record.defrecord(:r_t_bs_context, :t_bs_context, tail_unit: 1)
  Record.defrecord(:r_t_bs_matchable, :t_bs_matchable, tail_unit: 1)
  Record.defrecord(:r_t_float, :t_float, elements: :any)
  Record.defrecord(:r_t_fun, :t_fun, arity: :any, target: :any, type: :any)
  Record.defrecord(:r_t_integer, :t_integer, elements: :any)
  Record.defrecord(:r_t_number, :t_number, elements: :any)

  Record.defrecord(:r_t_map, :t_map,
    super_key: :any,
    super_value: :any
  )

  Record.defrecord(:r_t_cons, :t_cons,
    type: :any,
    terminator: :any
  )

  Record.defrecord(:r_t_list, :t_list,
    type: :any,
    terminator: :any
  )

  Record.defrecord(:r_t_tuple, :t_tuple, size: 0, exact: false, elements: %{})

  Record.defrecord(:r_t_union, :t_union,
    atom: :none,
    list: :none,
    number: :none,
    tuple_set: :none,
    other: :none
  )

  def will_succeed(:erlang, op, [lHS, rHS])
      when op === :+ or
             op === :- or op === :* do
    succeeds_if_smallish(lHS, rHS)
  end

  def will_succeed(:erlang, op, [lHS, rHS] = args)
      when op === :div or op === :rem do
    case {meet(lHS, r_t_integer()), meet(rHS, r_t_integer())} do
      {r_t_integer(elements: {_, _}) = ^lHS, r_t_integer(elements: {min, max}) = rHS}
      when (is_integer(min) and min > 0) or
             (is_integer(max) and max < -1) ->
        :yes

      {r_t_integer(), r_t_integer()} ->
        fails_on_conflict(:erlang, op, args)

      {_, _} ->
        :no
    end
  end

  def will_succeed(:erlang, :bsr = op, [lHS, rHS] = args) do
    case {meet(lHS, r_t_integer()), meet(rHS, r_t_integer())} do
      {r_t_integer(elements: {_, _}) = ^lHS, r_t_integer(elements: {minShift, _}) = rHS}
      when is_integer(minShift) and minShift >= 0 ->
        :yes

      {r_t_integer(), r_t_integer()} ->
        fails_on_conflict(:erlang, op, args)

      {_, _} ->
        :no
    end
  end

  def will_succeed(:erlang, :bsl = op, [lHS, rHS] = args) do
    case {meet(lHS, r_t_integer()), meet(rHS, r_t_integer())} do
      {^lHS, r_t_integer(elements: {_, maxShift}) = ^rHS}
      when is_integer(maxShift) and maxShift < 64 ->
        succeeds_if_smallish(lHS)

      {r_t_integer(), r_t_integer()} ->
        fails_on_conflict(:erlang, op, args)

      {_, _} ->
        :no
    end
  end

  def will_succeed(:erlang, :++, [lHS, _RHS]) do
    succeeds_if_type(lHS, proper_list())
  end

  def will_succeed(:erlang, :--, [_, _] = args) do
    succeeds_if_types(args, proper_list())
  end

  def will_succeed(:erlang, boolOp, [_, _] = args)
      when boolOp === :and or boolOp === :or do
    succeeds_if_types(args, :beam_types.make_boolean())
  end

  def will_succeed(:erlang, op, [_, _] = args)
      when op === :band or
             op === :bor or op === :bxor do
    succeeds_if_types(args, r_t_integer())
  end

  def will_succeed(:erlang, :bit_size, [arg]) do
    succeeds_if_type(arg, r_t_bitstring())
  end

  def will_succeed(:erlang, :byte_size, [arg]) do
    succeeds_if_type(arg, r_t_bitstring())
  end

  def will_succeed(:erlang, :element, [pos, tuple] = args) do
    case normalize(tuple) do
      r_t_tuple(exact: exact, size: sz) when sz >= 1 ->
        case meet(pos, r_t_integer(elements: {1, sz})) do
          ^pos ->
            :yes

          :none when exact ->
            :no

          _ ->
            fails_on_conflict(:erlang, :element, args)
        end

      _ ->
        fails_on_conflict(:erlang, :element, args)
    end
  end

  def will_succeed(:erlang, :hd, [arg]) do
    succeeds_if_type(arg, r_t_cons())
  end

  def will_succeed(:erlang, :is_function, [_, arity] = args) do
    case meet(arity, r_t_integer()) do
      r_t_integer(elements: {min, _}) = ^arity
      when is_integer(min) and
             min >= 0 ->
        :yes

      r_t_integer() ->
        fails_on_conflict(:erlang, :is_function, args)

      _ ->
        :no
    end
  end

  def will_succeed(:erlang, :is_map_key, [_Key, map]) do
    succeeds_if_type(map, r_t_map())
  end

  def will_succeed(:erlang, :length, [arg]) do
    succeeds_if_type(arg, proper_list())
  end

  def will_succeed(:erlang, :map_size, [arg]) do
    succeeds_if_type(arg, r_t_map())
  end

  def will_succeed(:erlang, :node, [arg]) do
    succeeds_if_type(arg, :identifier)
  end

  def will_succeed(:erlang, :and, [_, _] = args) do
    succeeds_if_types(args, :beam_types.make_boolean())
  end

  def will_succeed(:erlang, :not, [arg]) do
    succeeds_if_type(arg, :beam_types.make_boolean())
  end

  def will_succeed(:erlang, :or, [_, _] = args) do
    succeeds_if_types(args, :beam_types.make_boolean())
  end

  def will_succeed(:erlang, :xor, [_, _] = args) do
    succeeds_if_types(args, :beam_types.make_boolean())
  end

  def will_succeed(:erlang, :setelement, [pos, tuple0, _Value] = args) do
    posRange = r_t_integer(elements: {1, 1 <<< (24 - 1)})

    case {meet(pos, posRange), meet(tuple0, r_t_tuple(size: 1))} do
      {:none, _} ->
        :no

      {_, :none} ->
        :no

      {r_t_integer(elements: {min, max}) = ^pos, tuple} ->
        maxTupleSize = max_tuple_size(tuple)

        cond do
          maxTupleSize < min ->
            :no

          tuple0 === tuple and max <= maxTupleSize ->
            :yes

          true ->
            fails_on_conflict(:erlang, :setelement, args)
        end

      {_, _} ->
        fails_on_conflict(:erlang, :setelement, args)
    end
  end

  def will_succeed(:erlang, :size, [arg]) do
    argType = join(r_t_tuple(), r_t_bitstring())
    succeeds_if_type(arg, argType)
  end

  def will_succeed(:erlang, :tuple_size, [arg]) do
    succeeds_if_type(arg, r_t_tuple())
  end

  def will_succeed(:erlang, :tl, [arg]) do
    succeeds_if_type(arg, r_t_cons())
  end

  def will_succeed(:erlang, :raise, [class, _Reason, nil]) do
    case meet(
           class,
           r_t_atom(elements: [:error, :exit, :throw])
         ) do
      ^class ->
        :no

      :none ->
        :yes

      _ ->
        :maybe
    end
  end

  def will_succeed(mod, func, args) do
    arity = length(args)

    case :erl_bifs.is_safe(mod, func, arity) do
      true ->
        :yes

      false ->
        case :erl_bifs.is_exit_bif(mod, func, arity) do
          true ->
            :no

          false ->
            fails_on_conflict(mod, func, args)
        end
    end
  end

  defp max_tuple_size(r_t_union(tuple_set: [_ | _] = set) = union) do
    ^union = meet(union, r_t_tuple())

    arities =
      for {{arity, _Tag}, _Record} <- set do
        arity
      end

    :lists.max(arities)
  end

  defp max_tuple_size(r_t_tuple(exact: true, size: size)) do
    size
  end

  defp max_tuple_size(r_t_tuple(exact: false)) do
    1 <<< (24 - 1)
  end

  defp fails_on_conflict(mod, func, args) do
    case types(mod, func, args) do
      {:none, _, _} ->
        :no

      {_, argTypes, _} ->
        fails_on_conflict_1(args, argTypes)
    end
  end

  defp fails_on_conflict_1([argType | args], [required | types]) do
    case meet(argType, required) do
      :none ->
        :no

      _ ->
        fails_on_conflict_1(args, types)
    end
  end

  defp fails_on_conflict_1([], []) do
    :maybe
  end

  defp succeeds_if_types([lHS, rHS], required) do
    case {succeeds_if_type(lHS, required), succeeds_if_type(rHS, required)} do
      {:yes, :yes} ->
        :yes

      {:no, _} ->
        :no

      {_, :no} ->
        :no

      {_, _} ->
        :maybe
    end
  end

  defp succeeds_if_type(argType, required) do
    case meet(argType, required) do
      ^argType ->
        :yes

      :none ->
        :no

      _ ->
        :maybe
    end
  end

  defp succeeds_if_smallish(r_t_integer(elements: {min, max}))
       when abs(min) >>> 128 === 0 and
              abs(max) >>> 128 === 0 do
    :yes
  end

  defp succeeds_if_smallish(argType) do
    case succeeds_if_type(argType, r_t_number()) do
      :yes ->
        :maybe

      other ->
        other
    end
  end

  defp succeeds_if_smallish(lHS, rHS) do
    case {succeeds_if_smallish(lHS), succeeds_if_smallish(rHS)} do
      {:yes, :yes} ->
        :yes

      {:no, _} ->
        :no

      {_, :no} ->
        :no

      {_, _} ->
        :maybe
    end
  end

  def types(:erlang, :map_size, [_]) do
    sub_safe(r_t_integer(elements: {0, 1 <<< (58 - 1)}), [r_t_map()])
  end

  def types(:erlang, :tuple_size, [src]) do
    min =
      case normalize(meet(src, r_t_tuple())) do
        r_t_tuple(size: sz) ->
          sz

        _ ->
          0
      end

    max = 1 <<< (24 - 1)
    sub_safe(r_t_integer(elements: {min, max}), [r_t_tuple()])
  end

  def types(:erlang, :bit_size, [_]) do
    sub_safe(r_t_integer(elements: {0, 1 <<< (58 - 1)}), [r_t_bitstring()])
  end

  def types(:erlang, :byte_size, [_]) do
    sub_safe(r_t_integer(elements: {0, 1 <<< (58 - 1)}), [r_t_bitstring()])
  end

  def types(:erlang, :hd, [src]) do
    retType = erlang_hd_type(src)
    sub_safe(retType, [r_t_cons()])
  end

  def types(:erlang, :tl, [src]) do
    retType = erlang_tl_type(src)
    sub_safe(retType, [r_t_cons()])
  end

  def types(:erlang, :not, [_]) do
    bool = :beam_types.make_boolean()
    sub_safe(bool, [bool])
  end

  def types(:erlang, :length, [src]) do
    min =
      case src do
        r_t_cons() ->
          1

        _ ->
          0
      end

    sub_safe(
      r_t_integer(elements: {min, 1 <<< (58 - 1)}),
      [proper_list()]
    )
  end

  def types(:erlang, :and, [_, _]) do
    bool = :beam_types.make_boolean()
    sub_unsafe(bool, [bool, bool])
  end

  def types(:erlang, :or, [_, _]) do
    bool = :beam_types.make_boolean()
    sub_unsafe(bool, [bool, bool])
  end

  def types(:erlang, :xor, [_, _]) do
    bool = :beam_types.make_boolean()
    sub_unsafe(bool, [bool, bool])
  end

  def types(:erlang, op, [arg1, arg2])
      when op === :< or
             op === :"=<" or op === :>= or
             op === :> do
    {r1, r2} = {get_range(arg1), get_range(arg2)}

    case :beam_bounds.relop(op, r1, r2) do
      :maybe ->
        sub_unsafe(:beam_types.make_boolean(), [:any, :any])

      bool when is_boolean(bool) ->
        sub_unsafe(r_t_atom(elements: [bool]), [:any, :any])
    end
  end

  def types(:erlang, :is_atom, [type]) do
    sub_unsafe_type_test(type, r_t_atom())
  end

  def types(:erlang, :is_binary, [type]) do
    sub_unsafe_type_test(type, r_t_bs_matchable(tail_unit: 8))
  end

  def types(:erlang, :is_bitstring, [type]) do
    sub_unsafe_type_test(type, r_t_bs_matchable())
  end

  def types(:erlang, :is_boolean, [type]) do
    case :beam_types.is_boolean_type(type) do
      true ->
        sub_unsafe(r_t_atom(elements: [true]), [:any])

      false ->
        case meet(type, r_t_atom()) do
          r_t_atom(elements: [_ | _] = es) ->
            case any(&is_boolean/1, es) do
              true ->
                sub_unsafe(:beam_types.make_boolean(), [:any])

              false ->
                sub_unsafe(r_t_atom(elements: [false]), [:any])
            end

          r_t_atom() ->
            sub_unsafe(:beam_types.make_boolean(), [:any])

          :none ->
            sub_unsafe(r_t_atom(elements: [false]), [:any])
        end
    end
  end

  def types(:erlang, :is_float, [type]) do
    sub_unsafe_type_test(type, r_t_float())
  end

  def types(:erlang, :is_function, [type, arityType]) do
    retType =
      case meet(arityType, r_t_integer()) do
        :none ->
          :none

        r_t_integer(elements: {arity, arity}) when is_integer(arity) ->
          cond do
            arity < 0 ->
              :none

            0 <= arity and arity <= 255 ->
              case meet(type, r_t_fun(arity: arity)) do
                ^type ->
                  r_t_atom(elements: [true])

                :none ->
                  r_t_atom(elements: [false])

                _ ->
                  :beam_types.make_boolean()
              end

            arity > 255 ->
              r_t_atom(elements: [false])
          end

        r_t_integer() ->
          case meet(type, r_t_fun()) do
            :none ->
              r_t_atom(elements: [false])

            _ ->
              :beam_types.make_boolean()
          end
      end

    sub_unsafe(retType, [:any, :any])
  end

  def types(:erlang, :is_function, [type]) do
    sub_unsafe_type_test(type, r_t_fun())
  end

  def types(:erlang, :is_integer, [type]) do
    sub_unsafe_type_test(type, r_t_integer())
  end

  def types(:erlang, :is_list, [type]) do
    sub_unsafe_type_test(type, r_t_list())
  end

  def types(:erlang, :is_map, [type]) do
    sub_unsafe_type_test(type, r_t_map())
  end

  def types(:erlang, :is_number, [type]) do
    sub_unsafe_type_test(type, r_t_number())
  end

  def types(:erlang, :is_pid, [type]) do
    sub_unsafe_type_test(type, :pid)
  end

  def types(:erlang, :is_port, [type]) do
    sub_unsafe_type_test(type, :port)
  end

  def types(:erlang, :is_reference, [type]) do
    sub_unsafe_type_test(type, :reference)
  end

  def types(:erlang, :is_tuple, [type]) do
    sub_unsafe_type_test(type, r_t_tuple())
  end

  def types(:erlang, :band, [_, _] = args) do
    sub_unsafe(
      beam_bounds_type(:band, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, :bor, [_, _] = args) do
    sub_unsafe(
      beam_bounds_type(:bor, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, :bxor, [_, _] = args) do
    sub_unsafe(
      beam_bounds_type(:bxor, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, :bsl, [_, _] = args) do
    sub_unsafe(
      beam_bounds_type(:bsl, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, :bsr, [_, _] = args) do
    sub_unsafe(
      beam_bounds_type(:bsr, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, :bnot, [_]) do
    sub_unsafe(r_t_integer(), [r_t_integer()])
  end

  def types(:erlang, :float, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:erlang, :round, [_]) do
    sub_unsafe(r_t_integer(), [r_t_number()])
  end

  def types(:erlang, :floor, [_]) do
    sub_unsafe(r_t_integer(), [r_t_number()])
  end

  def types(:erlang, :ceil, [_]) do
    sub_unsafe(r_t_integer(), [r_t_number()])
  end

  def types(:erlang, :trunc, [_]) do
    sub_unsafe(r_t_integer(), [r_t_number()])
  end

  def types(:erlang, :/, [_, _]) do
    sub_unsafe(r_t_float(), [r_t_number(), r_t_number()])
  end

  def types(:erlang, :div, [_, _] = args) do
    sub_unsafe(
      beam_bounds_type(:div, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, :rem, args) do
    sub_unsafe(
      beam_bounds_type(:rem, r_t_integer(), args),
      [r_t_integer(), r_t_integer()]
    )
  end

  def types(:erlang, op, [lHS, rHS])
      when op === :+ or
             op === :- do
    case get_range(lHS, rHS, r_t_number()) do
      {type, {a, b}, {c, _D}} when is_integer(c) and c >= 0 ->
        r = :beam_bounds.bounds(op, {a, b}, {c, :"+inf"})

        retType =
          case type do
            :integer ->
              r_t_integer(elements: r)

            :number ->
              r_t_number(elements: r)
          end

        sub_unsafe(retType, [r_t_number(), r_t_number()])

      {type, {a, _B}, {c, d}}
      when op === :+ and
             is_integer(a) and a >= 0 ->
        r = :beam_bounds.bounds(op, {a, :"+inf"}, {c, d})

        retType =
          case type do
            :integer ->
              r_t_integer(elements: r)

            :number ->
              r_t_number(elements: r)
          end

        sub_unsafe(retType, [r_t_number(), r_t_number()])

      _ ->
        mixed_arith_types([lHS, rHS])
    end
  end

  def types(:erlang, :abs, [type]) do
    case meet(type, r_t_number()) do
      r_t_float() ->
        sub_unsafe(r_t_float(), [r_t_float()])

      r_t_integer(elements: r) ->
        retType = r_t_integer(elements: :beam_bounds.bounds(:abs, r))
        sub_unsafe(retType, [r_t_integer()])

      r_t_number(elements: r) ->
        retType = r_t_number(elements: :beam_bounds.bounds(:abs, r))
        sub_unsafe(retType, [r_t_number()])

      _ ->
        sub_unsafe(r_t_number(), [r_t_number()])
    end
  end

  def types(:erlang, :++, [lHS, rHS]) do
    listType = copy_list(lHS, :same_length, :proper)
    retType = join(listType, rHS)
    sub_unsafe(retType, [proper_list(), :any])
  end

  def types(:erlang, :--, [lHS, _]) do
    retType = copy_list(lHS, :new_length, :proper)
    sub_unsafe(retType, [proper_list(), proper_list()])
  end

  def types(:erlang, :atom_to_list, [_]) do
    sub_unsafe(
      proper_list(r_t_integer(elements: {0, 1_114_111})),
      [r_t_atom()]
    )
  end

  def types(:erlang, :iolist_to_binary, [_]) do
    argType = join(r_t_list(), r_t_bitstring(size_unit: 8))
    sub_unsafe(r_t_bitstring(size_unit: 8), [argType])
  end

  def types(:erlang, :iolist_size, [_]) do
    argType = join(r_t_list(), r_t_bitstring(size_unit: 8))
    sub_unsafe(r_t_integer(elements: {0, :"+inf"}), [argType])
  end

  def types(:erlang, :list_to_binary, [_]) do
    sub_unsafe(r_t_bitstring(size_unit: 8), [r_t_list()])
  end

  def types(:erlang, :list_to_bitstring, [_]) do
    sub_unsafe(r_t_bitstring(), [r_t_list()])
  end

  def types(:erlang, :list_to_integer, [_]) do
    sub_unsafe(r_t_integer(), [proper_cons()])
  end

  def types(:erlang, :list_to_integer, [_, _]) do
    sub_unsafe(r_t_integer(), [proper_cons(), r_t_integer()])
  end

  def types(:erlang, :alias, []) do
    sub_unsafe(:reference, [])
  end

  def types(:erlang, :alias, [_]) do
    sub_unsafe(:reference, [proper_list()])
  end

  def types(:erlang, :monitor, [_, _]) do
    sub_unsafe(:reference, [:any, :any])
  end

  def types(:erlang, :monitor, [_, _, _]) do
    sub_unsafe(:reference, [:any, :any, proper_list()])
  end

  def types(:erlang, :spawn, [_]) do
    sub_unsafe(:pid, [r_t_fun(arity: 0)])
  end

  def types(:erlang, :spawn, [_, _]) do
    sub_unsafe(:pid, [r_t_atom(), r_t_fun(arity: 0)])
  end

  def types(:erlang, :spawn, [_, _, _]) do
    sub_unsafe(:pid, [r_t_atom(), r_t_atom(), proper_list()])
  end

  def types(:erlang, :spawn_link, args) do
    types(:erlang, :spawn, args)
  end

  def types(:erlang, :spawn_monitor, [_]) do
    retType = make_two_tuple(:pid, :reference)
    sub_unsafe(retType, [r_t_fun(arity: 0)])
  end

  def types(:erlang, :spawn_monitor, [_, _]) do
    retType = make_two_tuple(:pid, :reference)
    sub_unsafe(retType, [r_t_atom(), r_t_fun(arity: 0)])
  end

  def types(:erlang, :spawn_monitor, [_, _, _]) do
    retType = make_two_tuple(:pid, :reference)
    sub_unsafe(retType, [r_t_atom(), r_t_atom(), proper_list()])
  end

  def types(:erlang, :spawn_request, [_ | _] = args)
      when length(args) <= 5 do
    sub_unsafe(
      :reference,
      for _ <- args do
        :any
      end
    )
  end

  def types(:erlang, :binary_part, [_, _]) do
    posLen = make_two_tuple(r_t_integer(), r_t_integer())
    binary = r_t_bitstring(size_unit: 8)
    sub_unsafe(binary, [binary, posLen])
  end

  def types(:erlang, :binary_part, [_, _, _]) do
    binary = r_t_bitstring(size_unit: 8)
    sub_unsafe(binary, [binary, r_t_integer(), r_t_integer()])
  end

  def types(:erlang, :is_map_key, [key, map]) do
    retType =
      case erlang_map_get_type(key, map) do
        :none ->
          :beam_types.make_atom(false)

        _ ->
          :beam_types.make_boolean()
      end

    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:erlang, :make_ref, []) do
    sub_unsafe(:reference, [])
  end

  def types(:erlang, :map_get, [key, map]) do
    retType = erlang_map_get_type(key, map)
    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:erlang, :node, [_]) do
    sub_unsafe(r_t_atom(), [:identifier])
  end

  def types(:erlang, :node, []) do
    sub_unsafe(r_t_atom(), [])
  end

  def types(:erlang, :self, []) do
    sub_unsafe(:pid, [])
  end

  def types(:erlang, :size, [_]) do
    argType = join(r_t_tuple(), r_t_bitstring())
    sub_unsafe(r_t_integer(), [argType])
  end

  def types(:erlang, :element, [pos, tuple0]) do
    posRange = r_t_integer(elements: {1, 1 <<< (24 - 1)})

    case meet(pos, posRange) do
      r_t_integer(elements: {index, index}) when index >= 1 ->
        case normalize(meet(tuple0, r_t_tuple(size: index))) do
          r_t_tuple(elements: es) = tuple ->
            retType = :beam_types.get_tuple_element(index, es)
            sub_unsafe(retType, [posRange, tuple])

          :none ->
            sub_unsafe(:none, [posRange, r_t_tuple()])
        end

      _ ->
        sub_unsafe(:any, [posRange, r_t_tuple()])
    end
  end

  def types(:erlang, :setelement, [posType, tupleType, argType]) do
    posRange = r_t_integer(elements: {1, 1 <<< (24 - 1)})

    retType =
      case meet(posType, posRange) do
        r_t_integer(elements: {same, same}) ->
          :beam_types.update_tuple(tupleType, [{same, argType}])

        r_t_integer() ->
          case normalize(meet(tupleType, r_t_tuple(size: 1))) do
            r_t_tuple() = t ->
              r_t_tuple(t, elements: %{})

            :none ->
              :none
          end

        :none ->
          :none
      end

    sub_unsafe(retType, [posRange, r_t_tuple(size: 1), :any])
  end

  def types(:erlang, :make_fun, [_, _, arity0]) do
    type =
      case meet(arity0, r_t_integer()) do
        r_t_integer(elements: {arity, arity})
        when arity >= 0 and
               arity <= 255 ->
          r_t_fun(arity: arity)

        r_t_integer() ->
          r_t_fun()

        _ ->
          :none
      end

    sub_unsafe(type, [r_t_atom(), r_t_atom(), r_t_integer()])
  end

  def types(:erlang, op, [lHS, rHS])
      when op === :min or
             op === :max do
    r1 = get_range(lHS)
    r2 = get_range(rHS)
    r = :beam_bounds.bounds(op, r1, r2)

    retType =
      case {lHS, rHS} do
        {r_t_integer(), r_t_integer()} ->
          r_t_integer(elements: r)

        {r_t_integer(), r_t_number()} ->
          r_t_number(elements: r)

        {r_t_number(), r_t_integer()} ->
          r_t_number(elements: r)

        {r_t_number(), r_t_number()} ->
          r_t_number(elements: r)

        {_, _} ->
          join(lHS, rHS)
      end

    sub_unsafe(retType, [:any, :any])
  end

  def types(:erlang, name, args) do
    arity = length(args)

    case :erl_bifs.is_exit_bif(:erlang, name, arity) do
      true ->
        {:none, args, false}

      false ->
        case :erl_internal.arith_op(name, arity) do
          true ->
            mixed_arith_types(args)

          false ->
            isTest =
              :erl_internal.new_type_test(
                name,
                arity
              ) or
                :erl_internal.comp_op(
                  name,
                  arity
                )

            retType =
              case isTest do
                true ->
                  :beam_types.make_boolean()

                false ->
                  :any
              end

            sub_unsafe(retType, duplicate(arity, :any))
        end
    end
  end

  def types(:math, :cos, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :cosh, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :sin, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :sinh, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :tan, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :tanh, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :acos, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :acosh, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :asin, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :asinh, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :atan, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :atanh, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :erf, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :erfc, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :exp, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :log, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :log2, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :log10, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :sqrt, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :atan2, [_, _]) do
    sub_unsafe(r_t_float(), [r_t_number(), r_t_number()])
  end

  def types(:math, :pow, [_, _]) do
    sub_unsafe(r_t_float(), [r_t_number(), r_t_number()])
  end

  def types(:math, :ceil, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :floor, [_]) do
    sub_unsafe(r_t_float(), [r_t_number()])
  end

  def types(:math, :fmod, [_, _]) do
    sub_unsafe(r_t_float(), [r_t_number(), r_t_number()])
  end

  def types(:math, :pi, []) do
    sub_unsafe(r_t_float(), [])
  end

  def types(:lists, :append, [_, _] = args) do
    types(:erlang, :++, args)
  end

  def types(:lists, :append, [_]) do
    sub_unsafe(:any, [proper_list()])
  end

  def types(:lists, :subtract, [_, _] = args) do
    types(:erlang, :--, args)
  end

  def types(:lists, :all, [_, _]) do
    sub_unsafe(:beam_types.make_boolean(), [:any, r_t_list()])
  end

  def types(:lists, :any, [_, _]) do
    sub_unsafe(:beam_types.make_boolean(), [:any, r_t_list()])
  end

  def types(:lists, :keymember, [_, _, _]) do
    sub_unsafe(:beam_types.make_boolean(), [:any, r_t_integer(), r_t_list()])
  end

  def types(:lists, :member, [_, _]) do
    sub_unsafe(:beam_types.make_boolean(), [:any, r_t_list()])
  end

  def types(:lists, :prefix, [_, _]) do
    sub_unsafe(:beam_types.make_boolean(), [r_t_list(), r_t_list()])
  end

  def types(:lists, :suffix, [_, _]) do
    sub_unsafe(:beam_types.make_boolean(), [r_t_list(), r_t_list()])
  end

  def types(:lists, :foldl, [fun, init, list]) do
    retType = lists_fold_type(fun, init, list)
    sub_unsafe(retType, [:any, :any, proper_list()])
  end

  def types(:lists, :foldr, [fun, init, list]) do
    retType = lists_fold_type(fun, init, list)
    sub_unsafe(retType, [:any, :any, proper_list()])
  end

  def types(:lists, :droplast, [list]) do
    retType = copy_list(list, :new_length, :proper)
    sub_unsafe(retType, [proper_list()])
  end

  def types(:lists, :dropwhile, [_Fun, list]) do
    retType = copy_list(list, :new_length, :maybe_improper)
    sub_unsafe(retType, [:any, r_t_list()])
  end

  def types(:lists, :duplicate, [_Count, element]) do
    sub_unsafe(proper_list(element), [r_t_integer(), :any])
  end

  def types(:lists, :filter, [_Fun, list]) do
    retType = copy_list(list, :new_length, :proper)
    sub_unsafe(retType, [:any, proper_list()])
  end

  def types(:lists, :flatten, [_]) do
    sub_unsafe(proper_list(), [proper_list()])
  end

  def types(:lists, :map, [fun, list]) do
    retType = lists_map_type(fun, list)
    sub_unsafe(retType, [:any, proper_list()])
  end

  def types(:lists, :reverse, [list]) do
    retType = copy_list(list, :same_length, :proper)
    sub_unsafe(retType, [proper_list()])
  end

  def types(:lists, :sort, [list]) do
    retType = copy_list(list, :same_length, :proper)
    sub_unsafe(retType, [proper_list()])
  end

  def types(:lists, :takewhile, [_Fun, list]) do
    retType = copy_list(list, :new_length, :proper)
    sub_unsafe(retType, [:any, r_t_list()])
  end

  def types(:lists, :usort, [list]) do
    retType = copy_list(list, :same_length, :proper)
    sub_unsafe(retType, [proper_list()])
  end

  def types(:lists, :zip, [_, _] = lists) do
    {retType, argType} = lists_zip_types(lists)
    sub_unsafe(retType, [argType, argType])
  end

  def types(:lists, :zipwith, [fun | [_, _] = lists]) do
    {retType, argType} = lists_zipwith_types(fun, lists)
    sub_unsafe(retType, [:any, argType, argType])
  end

  def types(:lists, :keyfind, [keyType, posType, _]) do
    tupleType =
      case meet(posType, r_t_integer()) do
        r_t_integer(elements: {index, index})
        when is_integer(index) and
               index >= 1 ->
          es = :beam_types.set_tuple_element(index, keyType, %{})
          r_t_tuple(size: index, elements: es)

        r_t_integer() ->
          r_t_tuple()

        :none ->
          :none
      end

    retType = join(tupleType, :beam_types.make_atom(false))
    sub_unsafe(retType, [:any, :any, r_t_list()])
  end

  def types(:lists, mapFold, [fun, init, list])
      when mapFold === :mapfoldl or mapFold === :mapfoldr do
    retType = lists_mapfold_type(fun, init, list)
    sub_unsafe(retType, [:any, :any, proper_list()])
  end

  def types(:lists, :partition, [_Fun, list]) do
    listType = copy_list(list, :new_length, :proper)
    retType = make_two_tuple(listType, listType)
    sub_unsafe(retType, [:any, proper_list()])
  end

  def types(:lists, :search, [_, _]) do
    tupleType =
      make_two_tuple(
        :beam_types.make_atom(:value),
        :any
      )

    retType = join(tupleType, :beam_types.make_atom(false))
    sub_unsafe(retType, [:any, r_t_list()])
  end

  def types(:lists, :splitwith, [_Fun, list]) do
    left = copy_list(list, :new_length, :proper)
    right = copy_list(list, :new_length, :maybe_improper)
    sub_unsafe(make_two_tuple(left, right), [:any, r_t_list()])
  end

  def types(:lists, :unzip, [list]) do
    retType = lists_unzip_type(2, list)
    sub_unsafe(retType, [proper_list()])
  end

  def types(:maps, :filter, [_Fun, map]) do
    retType =
      case meet(map, r_t_map()) do
        r_t_map() = t ->
          t

        _ ->
          :none
      end

    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:maps, :find, [key, map]) do
    tupleType =
      case erlang_map_get_type(key, map) do
        :none ->
          :none

        valueType ->
          make_two_tuple(:beam_types.make_atom(:ok), valueType)
      end

    retType = join(:beam_types.make_atom(:error), tupleType)
    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:maps, :fold, [fun, init, _Map]) do
    retType =
      case meet(fun, r_t_fun(arity: 3)) do
        r_t_fun(type: type) ->
          join(type, init)

        _ ->
          init
      end

    sub_unsafe(retType, [:any, :any, r_t_map()])
  end

  def types(:maps, :from_keys, [keys, value]) do
    keyType = erlang_hd_type(keys)

    valueType =
      case keyType do
        :none ->
          :none

        _ ->
          value
      end

    retType = r_t_map(super_key: keyType, super_value: valueType)
    sub_unsafe(retType, [proper_list(), :any])
  end

  def types(:maps, :from_list, [pairs]) do
    pairType = erlang_hd_type(pairs)

    retType =
      case normalize(
             meet(
               pairType,
               r_t_tuple(exact: true, size: 2)
             )
           ) do
        r_t_tuple(elements: es) ->
          sKey = :beam_types.get_tuple_element(1, es)
          sValue = :beam_types.get_tuple_element(2, es)
          r_t_map(super_key: sKey, super_value: sValue)

        :none when pairType === :none ->
          r_t_map(super_key: :none, super_value: :none)

        :none when pairType !== :none ->
          :none
      end

    sub_unsafe(retType, [proper_list()])
  end

  def types(:maps, :get, [_Key, _Map] = args) do
    types(:erlang, :map_get, args)
  end

  def types(:maps, :get, [key, map, default]) do
    retType =
      case erlang_map_get_type(key, map) do
        :none ->
          default

        valueType ->
          join(valueType, default)
      end

    sub_unsafe(retType, [:any, r_t_map(), :any])
  end

  def types(:maps, :keys, [map]) do
    retType =
      case meet(map, r_t_map()) do
        r_t_map(super_key: :none) ->
          nil

        r_t_map(super_key: sKey) ->
          proper_list(sKey)

        _ ->
          :none
      end

    sub_unsafe(retType, [r_t_map()])
  end

  def types(:maps, :map, [fun, map0]) do
    retType =
      case {meet(fun, r_t_fun(arity: 2)), meet(map0, r_t_map())} do
        {r_t_fun(type: funRet), r_t_map(super_value: sValue0) = map} ->
          sValue = join(funRet, sValue0)
          r_t_map(map, super_value: sValue)

        {:none, r_t_map()} ->
          r_t_map(super_key: :none, super_value: :none)

        {_, :none} ->
          :none
      end

    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:maps, :merge, [a, b]) do
    retType =
      case {meet(a, r_t_map()), meet(b, r_t_map())} do
        {r_t_map(super_key: sKeyA, super_value: sValueA),
         r_t_map(super_key: sKeyB, super_value: sValueB)} ->
          sKey = join(sKeyA, sKeyB)
          sValue = join(sValueA, sValueB)
          r_t_map(super_key: sKey, super_value: sValue)

        _ ->
          :none
      end

    sub_unsafe(retType, [r_t_map(), r_t_map()])
  end

  def types(:maps, :new, []) do
    retType = r_t_map(super_key: :none, super_value: :none)
    sub_unsafe(retType, [])
  end

  def types(:maps, :put, [key, value, map]) do
    retType =
      case meet(map, r_t_map()) do
        r_t_map(super_key: sKey0, super_value: sValue0) ->
          sKey = join(key, sKey0)
          sValue = join(value, sValue0)
          r_t_map(super_key: sKey, super_value: sValue)

        _ ->
          :none
      end

    sub_unsafe(retType, [:any, :any, r_t_map()])
  end

  def types(:maps, :remove, [key, map]) do
    retType = maps_remove_type(key, map)
    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:maps, :take, [key, map]) do
    tupleType =
      case erlang_map_get_type(key, map) do
        :none ->
          :none

        valueType ->
          mapType = meet(map, r_t_map())
          make_two_tuple(valueType, mapType)
      end

    retType = join(:beam_types.make_atom(:error), tupleType)
    sub_unsafe(retType, [:any, r_t_map()])
  end

  def types(:maps, :to_list, [map]) do
    retType =
      case meet(map, r_t_map()) do
        r_t_map(super_key: sKey, super_value: sValue) ->
          proper_list(make_two_tuple(sKey, sValue))

        _ ->
          :none
      end

    sub_unsafe(retType, [r_t_map()])
  end

  def types(:maps, :update_with, [_Key, fun, map0]) do
    retType =
      case {meet(fun, r_t_fun(arity: 1)), meet(map0, r_t_map())} do
        {r_t_fun(type: funRet), r_t_map(super_value: sValue0) = map}
        when funRet !== :none ->
          sValue = join(funRet, sValue0)
          r_t_map(map, super_value: sValue)

        _ ->
          :none
      end

    sub_unsafe(retType, [:any, r_t_fun(arity: 1), r_t_map()])
  end

  def types(:maps, :values, [map]) do
    retType =
      case meet(map, r_t_map()) do
        r_t_map(super_value: :none) ->
          nil

        r_t_map(super_value: sValue) ->
          proper_list(sValue)

        _ ->
          :none
      end

    sub_unsafe(retType, [r_t_map()])
  end

  def types(:maps, :with, [keys, map0]) do
    retType =
      case {erlang_hd_type(keys), meet(map0, r_t_map())} do
        {:none, _} ->
          r_t_map(super_key: :none, super_value: :none)

        {keysType, r_t_map(super_key: sKey0) = map} ->
          sKey = meet(keysType, sKey0)
          r_t_map(map, super_key: sKey)

        {_, _} ->
          :none
      end

    sub_unsafe(retType, [proper_list(), r_t_map()])
  end

  def types(:maps, :without, [keys, map]) do
    retType = maps_remove_type(erlang_hd_type(keys), map)
    sub_unsafe(retType, [proper_list(), r_t_map()])
  end

  def types(_, _, args) do
    sub_unsafe(
      :any,
      for _ <- args do
        :any
      end
    )
  end

  def arith_type({:bif, :-}, [arg]) do
    argTypes = [r_t_integer(elements: {0, 0}), arg]
    beam_bounds_type(:-, r_t_number(), argTypes)
  end

  def arith_type({:bif, :bnot}, [arg0]) do
    case meet(arg0, r_t_integer()) do
      :none ->
        :none

      r_t_integer(elements: r) ->
        r_t_integer(elements: :beam_bounds.bounds(:bnot, r))
    end
  end

  def arith_type({:bif, op}, [_, _] = argTypes)
      when op === :+ or
             op === :- or op === :* do
    beam_bounds_type(op, r_t_number(), argTypes)
  end

  def arith_type({:bif, op}, [_, _] = argTypes)
      when op === :band or op === :bor or op === :bsl or
             op === :bsr or op === :bxor or op === :div or
             op === :rem do
    beam_bounds_type(op, r_t_integer(), argTypes)
  end

  def arith_type(_Op, _Args) do
    :any
  end

  defp mixed_arith_types(args0) do
    [firstType | _] =
      args =
      for a <- args0 do
        meet(a, r_t_number())
      end

    retType =
      foldl(
        fn
          r_t_integer(), r_t_integer() ->
            r_t_integer()

          r_t_integer(), r_t_number() ->
            r_t_number()

          r_t_integer(), r_t_float() ->
            r_t_float()

          r_t_float(), r_t_integer() ->
            r_t_float()

          r_t_float(), r_t_number() ->
            r_t_float()

          r_t_float(), r_t_float() ->
            r_t_float()

          r_t_number(), r_t_integer() ->
            r_t_number()

          r_t_number(), r_t_float() ->
            r_t_float()

          r_t_number(), r_t_number() ->
            r_t_number()

          _, _ ->
            :none
        end,
        firstType,
        args
      )

    sub_unsafe(
      retType,
      for _ <- args do
        r_t_number()
      end
    )
  end

  defp erlang_hd_type(src) do
    case meet(src, r_t_cons()) do
      r_t_cons(type: type) ->
        type

      :none ->
        :none
    end
  end

  defp erlang_tl_type(src) do
    case meet(src, r_t_cons()) do
      r_t_cons(terminator: term) = cons ->
        join(cons, term)

      :none ->
        :none
    end
  end

  defp beam_bounds_type(op, type, [lHS, rHS]) do
    case get_range(lHS, rHS, type) do
      {_, :none, _} ->
        :none

      {_, _, :none} ->
        :none

      {:float, _R1, _R2} ->
        r_t_float()

      {:integer, r1, r2} ->
        r_t_integer(elements: :beam_bounds.bounds(op, r1, r2))

      {:number, r1, r2} ->
        r_t_number(elements: :beam_bounds.bounds(op, r1, r2))
    end
  end

  defp get_range(lHS, rHS, type) do
    get_range(meet(lHS, type), meet(rHS, type))
  end

  defp get_range(r_t_float() = lHS, r_t_float() = rHS) do
    {:float, get_range(lHS), get_range(rHS)}
  end

  defp get_range(r_t_integer() = lHS, r_t_integer() = rHS) do
    {:integer, get_range(lHS), get_range(rHS)}
  end

  defp get_range(lHS, rHS) do
    {:number, get_range(lHS), get_range(rHS)}
  end

  defp get_range(r_t_float()) do
    :any
  end

  defp get_range(r_t_integer(elements: r)) do
    r
  end

  defp get_range(r_t_number(elements: r)) do
    r
  end

  defp get_range(_) do
    :none
  end

  defp erlang_map_get_type(key, map) do
    case meet(map, r_t_map()) do
      r_t_map(super_key: sKey, super_value: sValue) ->
        case meet(sKey, key) do
          :none ->
            :none

          _ ->
            sValue
        end

      :none ->
        :none
    end
  end

  defp lists_fold_type(fun, init, list) do
    lists_fold_type_1(meet(fun, r_t_fun(arity: 2)), init, meet(list, r_t_list()))
  end

  defp lists_fold_type_1(_Fun, init, nil) do
    init
  end

  defp lists_fold_type_1(r_t_fun(type: type), _Init, r_t_cons()) do
    type
  end

  defp lists_fold_type_1(r_t_fun(type: type), init, r_t_list()) do
    join(type, init)
  end

  defp lists_fold_type_1(_Fun, _Init, _List) do
    :any
  end

  defp lists_map_type(fun, types) do
    case meet(fun, r_t_fun(arity: 1)) do
      r_t_fun(type: type) ->
        lists_map_type_1(types, type)

      :none ->
        :none
    end
  end

  defp lists_map_type_1(nil, _ElementType) do
    nil
  end

  defp lists_map_type_1(r_t_cons(), :none) do
    :none
  end

  defp lists_map_type_1(r_t_cons(), elementType) do
    proper_cons(elementType)
  end

  defp lists_map_type_1(_, :none) do
    nil
  end

  defp lists_map_type_1(_, elementType) do
    proper_list(elementType)
  end

  defp lists_mapfold_type(fun, init, list) do
    case {meet(fun, r_t_fun(type: r_t_tuple(size: 2))), meet(list, r_t_list())} do
      {_, nil} ->
        make_two_tuple(nil, init)

      {r_t_fun(type: r_t_tuple(elements: es)), listType} ->
        elementType = :beam_types.get_tuple_element(1, es)
        accType = :beam_types.get_tuple_element(2, es)
        lists_mapfold_type_1(listType, elementType, init, accType)

      {r_t_fun(type: :none), r_t_list()} ->
        make_two_tuple(nil, init)

      _ ->
        :none
    end
  end

  defp lists_mapfold_type_1(r_t_cons(), elementType, _Init, accType) do
    make_two_tuple(proper_cons(elementType), accType)
  end

  defp lists_mapfold_type_1(_, elementType, init, accType0) do
    accType = join(accType0, init)
    make_two_tuple(proper_list(elementType), accType)
  end

  defp lists_unzip_type(size, list) do
    case meet(
           list,
           r_t_list(type: r_t_tuple(exact: true, size: size))
         ) do
      :none ->
        :none

      listType ->
        es = lut_make_elements(lut_list_types(size, listType), 1, %{})
        r_t_tuple(size: size, exact: true, elements: es)
    end
  end

  defp lut_make_elements([type | types], index, es0) do
    es = :beam_types.set_tuple_element(index, type, es0)
    lut_make_elements(types, index + 1, es)
  end

  defp lut_make_elements([], _Index, es) do
    es
  end

  defp lut_list_types(size, r_t_cons(type: tuple)) do
    r_t_tuple(size: ^size, elements: es) = normalize(tuple)
    types = lut_element_types(1, size, es)

    for t <- types do
      proper_cons(t)
    end
  end

  defp lut_list_types(size, r_t_list(type: tuple)) do
    r_t_tuple(size: ^size, elements: es) = normalize(tuple)
    types = lut_element_types(1, size, es)

    for t <- types do
      proper_list(t)
    end
  end

  defp lut_list_types(size, nil) do
    :lists.duplicate(size, nil)
  end

  defp lut_element_types(index, max, %{}) when index > max do
    []
  end

  defp lut_element_types(index, max, es) do
    elementType = :beam_types.get_tuple_element(index, es)
    [elementType | lut_element_types(index + 1, max, es)]
  end

  defp lists_zip_types(types0) do
    types =
      for t <- types0 do
        meet(t, r_t_list(terminator: nil))
      end

    lists_zip_types_1(types, &proper_list/1, %{}, 1)
  end

  defp lists_zip_types_1([:none | _], _ListFun, _Es, _N) do
    {:none, nil}
  end

  defp lists_zip_types_1([nil | _], _ListFun, _Es, _N) do
    {nil, nil}
  end

  defp lists_zip_types_1([r_t_cons(type: type) | lists], _ListFun, es0, n) do
    es = :beam_types.set_tuple_element(n, type, es0)
    lists_zip_types_1(lists, &proper_cons/1, es, n + 1)
  end

  defp lists_zip_types_1([r_t_list(type: type) | lists], listFun, es0, n) do
    es = :beam_types.set_tuple_element(n, type, es0)
    lists_zip_types_1(lists, listFun, es, n + 1)
  end

  defp lists_zip_types_1([], listFun, es, n) do
    elementType = r_t_tuple(exact: true, size: n - 1, elements: es)
    retType = listFun.(elementType)
    argType = listFun.(:any)
    {retType, argType}
  end

  defp lists_zipwith_types(fun, types0) do
    elementType =
      case meet(fun, r_t_fun()) do
        r_t_fun(type: t) ->
          t

        :none ->
          :none
      end

    types =
      for t <- types0 do
        meet(t, r_t_list(terminator: nil))
      end

    lists_zipwith_type_1(types, elementType)
  end

  defp lists_zipwith_type_1([nil | _], _ElementType) do
    {nil, nil}
  end

  defp lists_zipwith_type_1([:none | _], _ElementType) do
    {:none, :any}
  end

  defp lists_zipwith_type_1([r_t_cons() | _Lists], :none) do
    {:none, :any}
  end

  defp lists_zipwith_type_1([r_t_cons() | _Lists], elementType) do
    retType = proper_cons(elementType)
    argType = proper_cons()
    {retType, argType}
  end

  defp lists_zipwith_type_1([r_t_list() | lists], elementType) do
    lists_zipwith_type_1(lists, elementType)
  end

  defp lists_zipwith_type_1([], :none) do
    {nil, nil}
  end

  defp lists_zipwith_type_1([], elementType) do
    retType = proper_list(elementType)
    argType = proper_list()
    {retType, argType}
  end

  defp maps_remove_type(key, map0) do
    case meet(map0, r_t_map()) do
      r_t_map(super_key: sKey0) = map ->
        case :beam_types.is_singleton_type(key) do
          true ->
            sKey = :beam_types.subtract(sKey0, key)
            r_t_map(map, super_key: sKey)

          false ->
            map
        end

      :none ->
        :none
    end
  end

  defp sub_unsafe_type_test(argType, required) do
    retType =
      case meet(argType, required) do
        ^argType ->
          r_t_atom(elements: [true])

        :none ->
          r_t_atom(elements: [false])

        _ ->
          :beam_types.make_boolean()
      end

    sub_unsafe(retType, [:any])
  end

  defp sub_unsafe(retType, argTypes) do
    {retType, argTypes, false}
  end

  defp sub_safe(retType, argTypes) do
    {retType, argTypes, true}
  end

  defp proper_cons() do
    r_t_cons(terminator: nil)
  end

  defp proper_cons(elementType) do
    r_t_cons(type: elementType, terminator: nil)
  end

  defp proper_list() do
    r_t_list(terminator: nil)
  end

  defp proper_list(elementType) do
    r_t_list(type: elementType, terminator: nil)
  end

  defp copy_list(list0, length, proper) do
    case {meet(list0, r_t_list()), length, proper} do
      {r_t_cons(type: type, terminator: term), :new_length, :maybe_improper} ->
        r_t_list(type: type, terminator: term)

      {r_t_cons(type: type), :new_length, :proper} ->
        r_t_list(type: type, terminator: nil)

      {r_t_cons() = t, _, :proper} ->
        r_t_cons(t, terminator: nil)

      {r_t_list() = t, _, :proper} ->
        r_t_list(t, terminator: nil)

      {:none, _, _} ->
        :none

      {list, _, _} ->
        list
    end
  end

  defp make_two_tuple(type1, type2) do
    es0 = :beam_types.set_tuple_element(1, type1, %{})
    es = :beam_types.set_tuple_element(2, type2, es0)
    r_t_tuple(size: 2, exact: true, elements: es)
  end

  defp normalize(t) do
    :beam_types.normalize(t)
  end

  defp join(a, b) do
    :beam_types.join(a, b)
  end

  defp meet(a, b) do
    :beam_types.meet(a, b)
  end
end
