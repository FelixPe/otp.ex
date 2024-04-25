defmodule :m_rand do
  use Bitwise
  defp uniform_range(range, %{next: next, bits: bits} = algHandler,
            r, v) do
    weakLowBits = :maps.get(:weak_low_bits, algHandler, 0)
    shift = bits - weakLowBits
    shiftMask = ~~~ (1 <<< weakLowBits - 1)
    rangeMinus1 = range - 1
    cond do
      range &&& rangeMinus1 === 0 ->
        {v1, r1, _} = uniform_range(range >>> bits, next, r, v,
                                      shiftMask, shift, bits)
        {v1 &&& rangeMinus1 + 1, {algHandler, r1}}
      true ->
        {v1, r1, b} = uniform_range(range >>> (bits - 2), next,
                                      r, v, shiftMask, shift, bits)
        i = rem(v1, range)
        cond do
          v1 - i <= 1 <<< b - range ->
            {i + 1, {algHandler, r1}}
          true ->
            {v2, r2} = next.(r1)
            uniform_range(range, algHandler, r2, v2)
        end
    end
  end

  defp uniform_range(range, next, r, v, shiftMask, shift, b) do
    cond do
      range <= 1 ->
        {v, r, b}
      true ->
        {v1, r1} = next.(r)
        uniform_range(range >>> shift, next, r1,
                        v &&& shiftMask <<< shift ||| v1, shiftMask, shift,
                        b + shift)
    end
  end

  def export_seed() do
    case (:erlang.get(:rand_seed)) do
      {%{type: alg}, algState} ->
        {alg, algState}
      _ ->
        :undefined
    end
  end

  def export_seed_s({%{type: alg}, algState}) do
    {alg, algState}
  end

  def seed(alg) do
    seed_put(seed_s(alg))
  end

  def seed_s({algHandler, _AlgState} = state)
      when is_map(algHandler) do
    state
  end

  def seed_s({alg, algState}) when is_atom(alg) do
    {algHandler, _SeedFun} = mk_alg(alg)
    {algHandler, algState}
  end

  def seed_s(alg) do
    seed_s(alg, default_seed())
  end

  defp default_seed() do
    {:erlang.phash2([{node(), self()}]),
       :erlang.system_time(), :erlang.unique_integer()}
  end

  def seed(alg, seed) do
    seed_put(seed_s(alg, seed))
  end

  def seed_s(:default, seed) do
    seed_s(:exsss, seed)
  end

  def seed_s(alg, seed) do
    {algHandler, seedFun} = mk_alg(alg)
    algState = seedFun.(seed)
    {algHandler, algState}
  end

  def uniform() do
    {x, state} = uniform_s(seed_get())
    _ = seed_put(state)
    x
  end

  def uniform(n) do
    {x, state} = uniform_s(n, seed_get())
    _ = seed_put(state)
    x
  end

  def uniform_s(state = {%{uniform: uniform}, _}) do
    uniform.(state)
  end

  def uniform_s({%{bits: bits, next: next} = algHandler, r0}) do
    {v, r1} = next.(r0)
    {(v >>> (bits - 53)) * 1.1102230246251565e-16,
       {algHandler, r1}}
  end

  def uniform_s({%{max: max, next: next} = algHandler, r0}) do
    {v, r1} = next.(r0)
    {v / (max + 1), {algHandler, r1}}
  end

  def uniform_s(n, state = {%{uniform_n: uniformN}, _})
      when (is_integer(n) and 1 <= n) do
    uniformN.(n, state)
  end

  def uniform_s(n, {%{bits: bits, next: next} = algHandler, r0})
      when (is_integer(n) and 1 <= n) do
    {v, r1} = next.(r0)
    maxMinusN = 1 <<< bits - n
    cond do
      0 <= maxMinusN ->
        cond do
          v < n ->
            {v + 1, {algHandler, r1}}
          true ->
            i = rem(v, n)
            cond do
              v - i <= maxMinusN ->
                {i + 1, {algHandler, r1}}
              true ->
                uniform_s(n, {algHandler, r1})
            end
        end
      true ->
        uniform_range(n, algHandler, r1, v)
    end
  end

  def uniform_s(n, {%{max: max, next: next} = algHandler, r0})
      when (is_integer(n) and 1 <= n) do
    {v, r1} = next.(r0)
    cond do
      n <= max ->
        {rem(v, n) + 1, {algHandler, r1}}
      true ->
        f = v / (max + 1)
        {trunc(f * n) + 1, {algHandler, r1}}
    end
  end

  def uniform_real() do
    {x, seed} = uniform_real_s(seed_get())
    _ = seed_put(seed)
    x
  end

  def uniform_real_s({%{bits: bits, next: next} = algHandler, r0}) do
    {v1, r1} = next.(r0)
    m1 = v1 >>> (bits - 56)
    cond do
      1 <<< 55 <= m1 ->
        {(m1 >>> 3) * :math.pow(2.0, - 53), {algHandler, r1}}
      1 <<< 54 <= m1 ->
        {(m1 >>> 2) * :math.pow(2.0, - 54), {algHandler, r1}}
      1 <<< 53 <= m1 ->
        {(m1 >>> 1) * :math.pow(2.0, - 55), {algHandler, r1}}
      1 <<< 52 <= m1 ->
        {m1 * :math.pow(2.0, - 56), {algHandler, r1}}
      true ->
        {v2, r2} = next.(r1)
        uniform_real_s(algHandler, next, m1, - 56, r2, v2, bits)
    end
  end

  def uniform_real_s({%{max: _, next: next} = algHandler, r0}) do
    {v1, r1} = next.(r0)
    m1 = v1 &&& (1 <<< 56 - 1)
    cond do
      1 <<< 55 <= m1 ->
        {(m1 >>> 3) * :math.pow(2.0, - 53), {algHandler, r1}}
      1 <<< 54 <= m1 ->
        {(m1 >>> 2) * :math.pow(2.0, - 54), {algHandler, r1}}
      1 <<< 53 <= m1 ->
        {(m1 >>> 1) * :math.pow(2.0, - 55), {algHandler, r1}}
      1 <<< 52 <= m1 ->
        {m1 * :math.pow(2.0, - 56), {algHandler, r1}}
      true ->
        {v2, r2} = next.(r1)
        uniform_real_s(algHandler, next, m1, - 56, r2, v2, 56)
    end
  end

  defp uniform_real_s(algHandler, _Next, m0, -1064, r1, v1, bits) do
    b0 = 53 - bc(m0, (1 <<< (52 - 1)), 52)
    {(m0 <<< b0 ||| (v1 >>> (bits - b0))) * :math.pow(2.0,
                                                        (- 1064 - b0)),
       {algHandler, r1}}
  end

  defp uniform_real_s(algHandler, next, m0, bitNo, r1, v1, bits) do
    cond do
      1 <<< 51 <= m0 ->
        {(m0 <<< 1 ||| (v1 >>> (bits - 1))) * :math.pow(2.0,
                                                          (bitNo - 1)),
           {algHandler, r1}}
      1 <<< 50 <= m0 ->
        {(m0 <<< 2 ||| (v1 >>> (bits - 2))) * :math.pow(2.0,
                                                          (bitNo - 2)),
           {algHandler, r1}}
      1 <<< 49 <= m0 ->
        {(m0 <<< 3 ||| (v1 >>> (bits - 3))) * :math.pow(2.0,
                                                          (bitNo - 3)),
           {algHandler, r1}}
      m0 == 0 ->
        m1 = v1 >>> (bits - 56)
        cond do
          1 <<< 55 <= m1 ->
            {(m1 >>> 3) * :math.pow(2.0, (bitNo - 53)),
               {algHandler, r1}}
          1 <<< 54 <= m1 ->
            {(m1 >>> 2) * :math.pow(2.0, (bitNo - 54)),
               {algHandler, r1}}
          1 <<< 53 <= m1 ->
            {(m1 >>> 1) * :math.pow(2.0, (bitNo - 55)),
               {algHandler, r1}}
          1 <<< 52 <= m1 ->
            {m1 * :math.pow(2.0, (bitNo - 56)), {algHandler, r1}}
          bitNo === - 1008 ->
            cond do
              1 <<< 42 <= m1 ->
                uniform_real_s(algHandler, next, m1, bitNo - 56, r1)
              true ->
                uniform_real_s({algHandler, r1})
            end
          true ->
            uniform_real_s(algHandler, next, m1, bitNo - 56, r1)
        end
      true ->
        b0 = 53 - bc(m0, (1 <<< (49 - 1)), 49)
        {(m0 <<< b0 ||| (v1 >>> (bits - b0))) * :math.pow(2.0,
                                                            (bitNo - b0)),
           {algHandler, r1}}
    end
  end

  defp uniform_real_s(%{bits: bits} = algHandler, next, m0, bitNo,
            r0) do
    {v1, r1} = next.(r0)
    uniform_real_s(algHandler, next, m0, bitNo, r1, v1,
                     bits)
  end

  defp uniform_real_s(%{max: _} = algHandler, next, m0, bitNo, r0) do
    {v1, r1} = next.(r0)
    uniform_real_s(algHandler, next, m0, bitNo, r1,
                     v1 &&& (1 <<< 56 - 1), 56)
  end

  def bytes(n) do
    {bytes, state} = bytes_s(n, seed_get())
    _ = seed_put(state)
    bytes
  end

  def bytes_s(n, {%{bits: bits, next: next} = algHandler, r})
      when (is_integer(n) and 0 <= n) do
    weakLowBits = :maps.get(:weak_low_bits, algHandler, 0)
    bytes_r(n, algHandler, next, r, bits, weakLowBits)
  end

  def bytes_s(n, {%{max: mask, next: next} = algHandler, r})
      when (is_integer(n) and 0 <= n and
              1 <<< 58 - 1 <= mask) do
    bits = 58
    weakLowBits = 2
    bytes_r(n, algHandler, next, r, bits, weakLowBits)
  end

  defp bytes_r(n, algHandler, next, r, bits, weakLowBits) do
    goodBytes = bits - weakLowBits >>> 3
    goodBits = goodBytes <<< 3
    shift = bits - goodBits
    bytes_r(n, algHandler, next, r, <<>>, goodBytes,
              goodBits, shift)
  end

  defp bytes_r(n0, algHandler, next, r0, bytes0, goodBytes,
            goodBits, shift)
      when goodBytes <<< 2 < n0 do
    {v1, r1} = next.(r0)
    {v2, r2} = next.(r1)
    {v3, r3} = next.(r2)
    {v4, r4} = next.(r3)
    bytes1 = <<bytes0 :: binary,
                 v1 >>> shift :: size(goodBits),
                 v2 >>> shift :: size(goodBits),
                 v3 >>> shift :: size(goodBits),
                 v4 >>> shift :: size(goodBits)>>
    n1 = n0 - (goodBytes <<< 2)
    bytes_r(n1, algHandler, next, r4, bytes1, goodBytes,
              goodBits, shift)
  end

  defp bytes_r(n0, algHandler, next, r0, bytes0, goodBytes,
            goodBits, shift)
      when goodBytes < n0 do
    {v, r1} = next.(r0)
    bytes1 = <<bytes0 :: binary,
                 v >>> shift :: size(goodBits)>>
    n1 = n0 - goodBytes
    bytes_r(n1, algHandler, next, r1, bytes1, goodBytes,
              goodBits, shift)
  end

  defp bytes_r(n, algHandler, next, r0, bytes, _GoodBytes,
            goodBits, _Shift) do
    {v, r1} = next.(r0)
    bits = n <<< 3
    shift = goodBits - bits
    {<<bytes :: binary, v >>> shift :: size(bits)>>,
       {algHandler, r1}}
  end

  def jump(state = {%{jump: jump}, _}) do
    jump.(state)
  end

  def jump({%{}, _}) do
    :erlang.error(:not_implemented)
  end

  def jump() do
    seed_put(jump(seed_get()))
  end

  def normal() do
    {x, seed} = normal_s(seed_get())
    _ = seed_put(seed)
    x
  end

  def normal(mean, variance) do
    mean + :math.sqrt(variance) * normal()
  end

  def normal_s(state0) do
    {sign, r, state} = get_52(state0)
    idx = r &&& (1 <<< 8 - 1)
    idx1 = idx + 1
    {ki, wi} = normal_kiwi(idx1)
    x = r * wi
    case (r < ki) do
      true when sign === 0 ->
        {x, state}
      true ->
        {- x, state}
      false when sign === 0 ->
        normal_s(idx, sign, x, state)
      false ->
        normal_s(idx, sign, - x, state)
    end
  end

  def normal_s(mean, variance, state0) when variance > 0 do
    {x, state} = normal_s(state0)
    {mean + :math.sqrt(variance) * x, state}
  end

  defp seed_put(seed) do
    :erlang.put(:rand_seed, seed)
    seed
  end

  defp seed_get() do
    case (:erlang.get(:rand_seed)) do
      :undefined ->
        seed(:exsss)
      old ->
        old
    end
  end

  defp mk_alg(:exs64) do
    {%{type: :exs64, max: 1 <<< 64 - 1,
         next: &exs64_next/1},
       &exs64_seed/1}
  end

  defp mk_alg(:exsplus) do
    {%{type: :exsplus, max: 1 <<< 58 - 1,
         next: &exsp_next/1, jump: &exsplus_jump/1},
       &exsplus_seed/1}
  end

  defp mk_alg(:exsp) do
    {%{type: :exsp, bits: 58, weak_low_bits: 1,
         next: &exsp_next/1, uniform: &exsp_uniform/1,
         uniform_n: &exsp_uniform/2, jump: &exsplus_jump/1},
       &exsplus_seed/1}
  end

  defp mk_alg(:exsss) do
    {%{type: :exsss, bits: 58, next: &exsss_next/1,
         uniform: &exsss_uniform/1, uniform_n: &exsss_uniform/2,
         jump: &exsplus_jump/1},
       &exsss_seed/1}
  end

  defp mk_alg(:exs1024) do
    {%{type: :exs1024, max: 1 <<< 64 - 1,
         next: &exs1024_next/1, jump: &exs1024_jump/1},
       &exs1024_seed/1}
  end

  defp mk_alg(:exs1024s) do
    {%{type: :exs1024s, bits: 64, weak_low_bits: 3,
         next: &exs1024_next/1, jump: &exs1024_jump/1},
       &exs1024_seed/1}
  end

  defp mk_alg(:exrop) do
    {%{type: :exrop, bits: 58, weak_low_bits: 1,
         next: &exrop_next/1, uniform: &exrop_uniform/1,
         uniform_n: &exrop_uniform/2, jump: &exrop_jump/1},
       &exrop_seed/1}
  end

  defp mk_alg(:exro928ss) do
    {%{type: :exro928ss, bits: 58, next: &exro928ss_next/1,
         uniform: &exro928ss_uniform/1,
         uniform_n: &exro928ss_uniform/2, jump: &exro928_jump/1},
       &exro928_seed/1}
  end

  defp mk_alg(:dummy = name) do
    {%{type: name, bits: 58, next: &dummy_next/1,
         uniform: &dummy_uniform/1, uniform_n: &dummy_uniform/2},
       &dummy_seed/1}
  end

  defp exs64_seed(l) when is_list(l) do
    [r] = seed64_nz(1, l)
    r
  end

  defp exs64_seed(a) when is_integer(a) do
    [r] = seed64(1, a)
    r
  end

  defp exs64_seed({a1, a2, a3}) do
    {v1,
       _} = exs64_next(a1 &&& (1 <<< 32 - 1) * 4294967197 + 1)
    {v2,
       _} = exs64_next(a2 &&& (1 <<< 32 - 1) * 4294967231 + 1)
    {v3,
       _} = exs64_next(a3 &&& (1 <<< 32 - 1) * 4294967279 + 1)
    rem(v1 * v2 * v3, 1 <<< 64 - 1 - 1) + 1
  end

  defp exs64_next(r) do
    r1 = r ^^^ (r >>> 12)
    r2 = r1 ^^^ (r1 &&& (1 <<< (64 - 25) - 1) <<< 25)
    r3 = r2 ^^^ (r2 >>> 27)
    {r3 * 2685821657736338717 &&& (1 <<< 64 - 1), r3}
  end

  defp exsplus_seed(l) when is_list(l) do
    [s0, s1] = seed58_nz(2, l)
    [s0 | s1]
  end

  defp exsplus_seed(x) when is_integer(x) do
    [s0, s1] = seed58(2, x)
    [s0 | s1]
  end

  defp exsplus_seed({a1, a2, a3}) do
    {_,
       r1} = exsp_next([(a1 * 4294967197 + 1) &&& (1 <<< 58 - 1) |
                            (a2 * 4294967231 + 1) &&& (1 <<< 58 - 1)])
    {_,
       r2} = exsp_next([(a3 * 4294967279 + 1) &&& (1 <<< 58 - 1) |
                            tl(r1)])
    r2
  end

  defp exsss_seed(l) when is_list(l) do
    [s0, s1] = seed58_nz(2, l)
    [s0 | s1]
  end

  defp exsss_seed(x) when is_integer(x) do
    [s0, s1] = seed58(2, x)
    [s0 | s1]
  end

  defp exsss_seed({a1, a2, a3}) do
    {_, x0} = seed58(a1)
    {s0, x1} = seed58(a2 ^^^ x0)
    {s1, _} = seed58(a3 ^^^ x1)
    [s0 | s1]
  end

  def exsp_next([s1 | s0]) do
    s0_1 = s0 &&& (1 <<< 58 - 1)
    newS1 = ((
               s1_b = s1 &&& (1 <<< 58 - 1) ^^^ (s1 &&& (1 <<< (58 - 24) - 1) <<< 24)
               s1_b ^^^ s0_1 ^^^ (s1_b >>> 11) ^^^ (s0_1 >>> 41)
             ))
    {(s0_1 + newS1) &&& (1 <<< 58 - 1), [s0_1 | newS1]}
  end

  defp exsss_next([s1 | s0]) do
    s0_1 = s0 &&& (1 <<< 58 - 1)
    newS1 = ((
               s1_b = s1 &&& (1 <<< 58 - 1) ^^^ (s1 &&& (1 <<< (58 - 24) - 1) <<< 24)
               s1_b ^^^ s0_1 ^^^ (s1_b >>> 11) ^^^ (s0_1 >>> 41)
             ))
    {(
       v_1 = s0_1 + (s0_1 &&& (1 <<< (58 - 2) - 1) <<< 2)
       v_2 = v_1 &&& (1 <<< (58 - 7) - 1) <<< 7 ||| (v_1 >>> (58 - 7)) &&& (1 <<< 7 - 1)
       (v_2 + (v_2 &&& (1 <<< (58 - 3) - 1) <<< 3)) &&& (1 <<< 58 - 1)
     ),
       [s0_1 | newS1]}
  end

  defp exsp_uniform({algHandler, r0}) do
    {i, r1} = exsp_next(r0)
    {(i >>> (58 - 53)) * 1.1102230246251565e-16,
       {algHandler, r1}}
  end

  defp exsss_uniform({algHandler, r0}) do
    {i, r1} = exsss_next(r0)
    {(i >>> (58 - 53)) * 1.1102230246251565e-16,
       {algHandler, r1}}
  end

  defp exsp_uniform(range, {algHandler, r}) do
    {v, r1} = exsp_next(r)
    maxMinusRange = 1 <<< 58 - range
    cond do
      0 <= maxMinusRange ->
        cond do
          v < range ->
            {v + 1, {algHandler, r1}}
          true ->
            i = rem(v, range)
            cond do
              v - i <= maxMinusRange ->
                {i + 1, {algHandler, r1}}
              true ->
                exsp_uniform(range, {algHandler, r1})
            end
        end
      true ->
        uniform_range(range, algHandler, r1, v)
    end
  end

  defp exsss_uniform(range, {algHandler, r}) do
    {v, r1} = exsss_next(r)
    maxMinusRange = 1 <<< 58 - range
    cond do
      0 <= maxMinusRange ->
        cond do
          v < range ->
            {v + 1, {algHandler, r1}}
          true ->
            i = rem(v, range)
            cond do
              v - i <= maxMinusRange ->
                {i + 1, {algHandler, r1}}
              true ->
                exsss_uniform(range, {algHandler, r1})
            end
        end
      true ->
        uniform_range(range, algHandler, r1, v)
    end
  end

  defp exsplus_jump({algHandler, s}) do
    {algHandler, exsp_jump(s)}
  end

  def exsp_jump(s) do
    {s1, aS1} = exsplus_jump(s, [0 | 0], 13386170678560663,
                               58)
    {_, aS2} = exsplus_jump(s1, aS1, 235826144310425740, 58)
    aS2
  end

  defp exsplus_jump(s, aS, _, 0) do
    {s, aS}
  end

  defp exsplus_jump(s, [aS0 | aS1], j, n) do
    {_, nS} = exsp_next(s)
    case (j &&& (1 <<< 1 - 1)) do
      1 ->
        [s0 | s1] = s
        exsplus_jump(nS, [aS0 ^^^ s0 | aS1 ^^^ s1], j >>> 1,
                       n - 1)
      0 ->
        exsplus_jump(nS, [aS0 | aS1], j >>> 1, n - 1)
    end
  end

  defp exs1024_seed(l) when is_list(l) do
    {seed64_nz(16, l), []}
  end

  defp exs1024_seed(x) when is_integer(x) do
    {seed64(16, x), []}
  end

  defp exs1024_seed({a1, a2, a3}) do
    b1 = (a1 &&& (1 <<< 21 - 1) + 1) * 2097131 &&& (1 <<< 21 - 1)
    b2 = (a2 &&& (1 <<< 21 - 1) + 1) * 2097133 &&& (1 <<< 21 - 1)
    b3 = (a3 &&& (1 <<< 21 - 1) + 1) * 2097143 &&& (1 <<< 21 - 1)
    {exs1024_gen1024(b1 <<< 43 ||| (b2 <<< 22) ||| (b3 <<< 1) ||| 1),
       []}
  end

  defp exs1024_gen1024(r) do
    exs1024_gen1024(16, r, [])
  end

  defp exs1024_gen1024(0, _, l) do
    l
  end

  defp exs1024_gen1024(n, r, l) do
    {x, r2} = exs64_next(r)
    exs1024_gen1024(n - 1, r2, [x | l])
  end

  defp exs1024_calc(s0, s1) do
    s11 = s1 ^^^ (s1 &&& (1 <<< (64 - 31) - 1) <<< 31)
    s12 = s11 ^^^ (s11 >>> 11)
    s01 = s0 ^^^ (s0 >>> 30)
    nS1 = s01 ^^^ s12
    {nS1 * 1181783497276652981 &&& (1 <<< 64 - 1), nS1}
  end

  defp exs1024_next({[s0, s1 | l3], rL}) do
    {x, nS1} = exs1024_calc(s0, s1)
    {x, {[nS1 | l3], [s0 | rL]}}
  end

  defp exs1024_next({[h], rL}) do
    nL = [h | :lists.reverse(rL)]
    exs1024_next({nL, []})
  end

  defp exs1024_jump({algHandler, {l, rL}}) do
    p = length(rL)
    aS = exs1024_jump({l, rL},
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [114527183042123105, 160423628620659260,
                                                 284733707589872850,
                                                     164435740288387503,
                                                         259572741793888962,
                                                             215793509705812255,
                                                                 228241955430903492,
                                                                     221708554683218499,
                                                                         212006596549813798,
                                                                             139215019150089363,
                                                                                 23964000621384961,
                                                                                     55201052708218217,
                                                                                         112969240468397636,
                                                                                             22130735059088892,
                                                                                                 244278597799509466,
                                                                                                     220175845070832114,
                                                                                                         43243288828],
                        10185424423732253, 58, 1024)
    {aSL, aSR} = :lists.split(16 - p, aS)
    {algHandler, {aSL, :lists.reverse(aSR)}}
  end

  defp exs1024_jump(_, aS, _, _, _, 0) do
    aS
  end

  defp exs1024_jump(s, aS, [h | t], _, 0, tN) do
    exs1024_jump(s, aS, t, h, 58, tN)
  end

  defp exs1024_jump({l, rL}, aS, jL, j, n, tN) do
    {_, nS} = exs1024_next({l, rL})
    case (j &&& (1 <<< 1 - 1)) do
      1 ->
        aS2 = :lists.zipwith(fn x, y ->
                                  x ^^^ y
                             end,
                               aS, l ++ :lists.reverse(rL))
        exs1024_jump(nS, aS2, jL, j >>> 1, n - 1, tN - 1)
      0 ->
        exs1024_jump(nS, aS, jL, j >>> 1, n - 1, tN - 1)
    end
  end

  def exro928_seed(l) when is_list(l) do
    {seed58_nz(16, l), []}
  end

  def exro928_seed(x) when is_integer(x) do
    {seed58(16, x), []}
  end

  def exro928_seed({a1, a2, a3}) do
    {s0, x0} = seed58(a1)
    {s1, x1} = seed58(a2 ^^^ x0)
    {s2, x2} = seed58(a3 ^^^ x1)
    {[s0, s1, s2 | seed58(13, x2)], []}
  end

  defp exro928ss_next({[s15, s0 | ss], rs}) do
    sR = exro928_next_state(ss, rs, s15, s0)
    {(
       v_0 = s0 + (s0 &&& (1 <<< (58 - 2) - 1) <<< 2)
       v_1 = v_0 &&& (1 <<< (58 - 7) - 1) <<< 7 ||| (v_0 >>> (58 - 7)) &&& (1 <<< 7 - 1)
       (v_1 + (v_1 &&& (1 <<< (58 - 3) - 1) <<< 3)) &&& (1 <<< 58 - 1)
     ),
       sR}
  end

  defp exro928ss_next({[s15], rs}) do
    exro928ss_next({[s15 | :lists.reverse(rs)], []})
  end

  def exro928_next({[s15, s0 | ss], rs}) do
    sR = exro928_next_state(ss, rs, s15, s0)
    {{s15, s0}, sR}
  end

  def exro928_next({[s15], rs}) do
    exro928_next({[s15 | :lists.reverse(rs)], []})
  end

  def exro928_next_state({[s15, s0 | ss], rs}) do
    exro928_next_state(ss, rs, s15, s0)
  end

  def exro928_next_state({[s15], rs}) do
    [s0 | ss] = :lists.reverse(rs)
    exro928_next_state(ss, [], s15, s0)
  end

  defp exro928_next_state(ss, rs, s15, s0) do
    s0_1 = s0 &&& (1 <<< 58 - 1)
    q = s15 &&& (1 <<< 58 - 1) ^^^ s0_1
    newS15 = s0_1 &&& (1 <<< (58 - 44) - 1) <<< 44 ||| (s0_1 >>> (58 - 44)) ^^^ q ^^^ (q &&& (1 <<< (58 - 9) - 1) <<< 9)
    newS0 = q &&& (1 <<< (58 - 45) - 1) <<< 45 ||| (q >>> (58 - 45))
    {[newS0 | ss], [newS15 | rs]}
  end

  defp exro928ss_uniform({algHandler, sR}) do
    {v, newSR} = exro928ss_next(sR)
    {(v >>> (58 - 53)) * 1.1102230246251565e-16,
       {algHandler, newSR}}
  end

  defp exro928ss_uniform(range, {algHandler, sR}) do
    {v, newSR} = exro928ss_next(sR)
    maxMinusRange = 1 <<< 58 - range
    cond do
      0 <= maxMinusRange ->
        cond do
          v < range ->
            {v + 1, {algHandler, newSR}}
          true ->
            i = rem(v, range)
            cond do
              v - i <= maxMinusRange ->
                {i + 1, {algHandler, newSR}}
              true ->
                exro928ss_uniform(range, {algHandler, newSR})
            end
        end
      true ->
        uniform_range(range, algHandler, newSR, v)
    end
  end

  defp exro928_jump({algHandler, sR}) do
    {algHandler, exro928_jump_2pow512(sR)}
  end

  def exro928_jump_2pow512(sR) do
    polyjump(sR, &exro928_next_state/1,
               [290573448171827402, 382251779910418577,
                                        423857156240780192, 317638803078791815,
                                                                312577798172065765,
                                                                    305801842905235492,
                                                                        450887821400921554,
                                                                            490154825290594607,
                                                                                507224882549817556,
                                                                                    305131922350994371,
                                                                                        524004876356613068,
                                                                                            399286492428034246,
                                                                                                556129459533271918,
                                                                                                    302163523288674092,
                                                                                                        295571835370094372,
                                                                                                            487547435355635071])
  end

  def exro928_jump_2pow20(sR) do
    polyjump(sR, &exro928_next_state/1,
               [412473694820566502, 432883605991317039,
                                        525373508288112196, 403915169708599875,
                                                                319067783491633768,
                                                                    301226760020322060,
                                                                        311627678308842608,
                                                                            376040681981803602,
                                                                                339701046172540810,
                                                                                    406476937554306621,
                                                                                        319178240279900411,
                                                                                            538961455727032748,
                                                                                                343829982822907227,
                                                                                                    562090186051299616,
                                                                                                        294421712295949406,
                                                                                                            517056752316592047])
  end

  defp exrop_seed(l) when is_list(l) do
    [s0, s1] = seed58_nz(2, l)
    [s0 | s1]
  end

  defp exrop_seed(x) when is_integer(x) do
    [s0, s1] = seed58(2, x)
    [s0 | s1]
  end

  defp exrop_seed({a1, a2, a3}) do
    [_ |
         s1] = exrop_next_s((a1 * 4294967197 + 1) &&& (1 <<< 58 - 1),
                              (a2 * 4294967231 + 1) &&& (1 <<< 58 - 1))
    exrop_next_s((a3 * 4294967279 + 1) &&& (1 <<< 58 - 1),
                   s1)
  end

  defp exrop_next_s(s0, s1) do
    (
      s1_a = s1 ^^^ s0
      [s0 &&& (1 <<< (58 - 24) - 1) <<< 24 ||| (s0 >>> (58 - 24)) ^^^ s1_a ^^^ (s1_a &&& (1 <<< (58 - 2) - 1) <<< 2) |
           s1_a &&& (1 <<< (58 - 35) - 1) <<< 35 ||| (s1_a >>> (58 - 35))]
    )
  end

  defp exrop_next([s0 | s1]) do
    {(s0 + s1) &&& (1 <<< 58 - 1),
       (
         s1_a = s1 ^^^ s0
         [s0 &&& (1 <<< (58 - 24) - 1) <<< 24 ||| (s0 >>> (58 - 24)) ^^^ s1_a ^^^ (s1_a &&& (1 <<< (58 - 2) - 1) <<< 2) |
              s1_a &&& (1 <<< (58 - 35) - 1) <<< 35 ||| (s1_a >>> (58 - 35))]
       )}
  end

  defp exrop_uniform({algHandler, r}) do
    {v, r1} = exrop_next(r)
    {(v >>> (58 - 53)) * 1.1102230246251565e-16,
       {algHandler, r1}}
  end

  defp exrop_uniform(range, {algHandler, r}) do
    {v, r1} = exrop_next(r)
    maxMinusRange = 1 <<< 58 - range
    cond do
      0 <= maxMinusRange ->
        cond do
          v < range ->
            {v + 1, {algHandler, r1}}
          true ->
            i = rem(v, range)
            cond do
              v - i <= maxMinusRange ->
                {i + 1, {algHandler, r1}}
              true ->
                exrop_uniform(range, {algHandler, r1})
            end
        end
      true ->
        uniform_range(range, algHandler, r1, v)
    end
  end

  defp exrop_jump({algHandler, s}) do
    [j |
         js] = [1 <<< 58 ||| 49452476321943384982939338509431082 &&& (1 <<< 58 - 1),
                    49452476321943384982939338509431082 >>> 58]
    {algHandler, exrop_jump(s, 0, 0, j, js)}
  end

  defp exrop_jump(_S, s0, s1, 0, []) do
    [s0 | s1]
  end

  defp exrop_jump(s, s0, s1, 1, [j | js]) do
    exrop_jump(s, s0, s1, j, js)
  end

  defp exrop_jump([s__0 | s__1] = _S, s0, s1, j, js) do
    case (j &&& (1 <<< 1 - 1)) do
      1 ->
        newS = exrop_next_s(s__0, s__1)
        exrop_jump(newS, s0 ^^^ s__0, s1 ^^^ s__1, j >>> 1, js)
      0 ->
        newS = exrop_next_s(s__0, s__1)
        exrop_jump(newS, s0, s1, j >>> 1, js)
    end
  end

  defp dummy_uniform(_Range, {algHandler, r}) do
    {1, {algHandler, r ^^^ (1 <<< 58 - 1)}}
  end

  defp dummy_next(r) do
    {r, r ^^^ (1 <<< 58 - 1)}
  end

  defp dummy_uniform({algHandler, r}) do
    {0.5, {algHandler, r ^^^ (1 <<< 58 - 1)}}
  end

  defp dummy_seed(l) when is_list(l) do
    case (l) do
      [] ->
        :erlang.error(:zero_seed)
      [x] when is_integer(x) ->
        x &&& (1 <<< 58 - 1)
      [x | _] when is_integer(x) ->
        :erlang.error(:too_many_seed_integers)
      [_ | _] ->
        :erlang.error(:non_integer_seed)
    end
  end

  defp dummy_seed(x) when is_integer(x) do
    {z1, _} = splitmix64_next(x)
    z1 &&& (1 <<< 58 - 1)
  end

  defp dummy_seed({a1, a2, a3}) do
    {_, x1} = splitmix64_next(a1)
    {_, x2} = splitmix64_next(a2 ^^^ x1)
    {z3, _} = splitmix64_next(a3 ^^^ x2)
    z3 &&& (1 <<< 58 - 1)
  end

  def mwc59(cX) when (is_integer(cX) and 1 <= cX and
                     cX < 133850370 <<< 32 - 1) do
    c = cX >>> 32
    x = cX &&& (1 <<< 32 - 1)
    133850370 * x + c
  end

  def mwc59_value32(cX1) when (is_integer(cX1) and 1 <= cX1 and
                      cX1 < 133850370 <<< 32 - 1) do
    cX = cX1 &&& (1 <<< 32 - 1)
    cX ^^^ (cX &&& (1 <<< (32 - 8) - 1) <<< 8)
  end

  def mwc59_value(cX) when (is_integer(cX) and 1 <= cX and
                     cX < 133850370 <<< 32 - 1) do
    cX2 = cX ^^^ (cX &&& (1 <<< (59 - 4) - 1) <<< 4)
    cX2 ^^^ (cX2 &&& (1 <<< (59 - 27) - 1) <<< 27)
  end

  def mwc59_float(cX1) when (is_integer(cX1) and 1 <= cX1 and
                      cX1 < 133850370 <<< 32 - 1) do
    cX = cX1 &&& (1 <<< 53 - 1)
    cX2 = cX ^^^ (cX &&& (1 <<< (53 - 4) - 1) <<< 4)
    cX3 = cX2 ^^^ (cX2 &&& (1 <<< (53 - 27) - 1) <<< 27)
    cX3 * 1.1102230246251565e-16
  end

  def mwc59_seed() do
    {a1, a2, a3} = default_seed()
    x1 = hash58(a1)
    x2 = hash58(a2)
    x3 = hash58(a3)
    x1 ^^^ x2 ^^^ x3 + 1
  end

  def mwc59_seed(s) when (is_integer(s) and 0 <= s and
                    s <= 1 <<< 58 - 1) do
    hash58(s) + 1
  end

  defp hash58(x) do
    x0 = x &&& (1 <<< 58 - 1)
    x1 = (x0 ^^^ (x0 >>> 29)) * 239165597161983181 &&& (1 <<< 58 - 1)
    x2 = (x1 ^^^ (x1 >>> 29)) * 58188346220211283 &&& (1 <<< 58 - 1)
    x2 ^^^ (x2 >>> 29)
  end

  defp seed58_nz(n, ss) do
    seed_nz(n, ss, 58, false)
  end

  defp seed64_nz(n, ss) do
    seed_nz(n, ss, 64, false)
  end

  defp seed_nz(_N, [], _M, false) do
    :erlang.error(:zero_seed)
  end

  defp seed_nz(0, [_ | _], _M, _NZ) do
    :erlang.error(:too_many_seed_integers)
  end

  defp seed_nz(0, [], _M, _NZ) do
    []
  end

  defp seed_nz(n, [], m, true) do
    [0 | seed_nz(n - 1, [], m, true)]
  end

  defp seed_nz(n, [s | ss], m, nZ) do
    cond do
      is_integer(s) ->
        r = s &&& (1 <<< m - 1)
        [r | seed_nz(n - 1, ss, m, nZ or r !== 0)]
      true ->
        :erlang.error(:non_integer_seed)
    end
  end

  def seed58(0, _X) do
    []
  end

  def seed58(n, x) do
    {z, newX} = seed58(x)
    [z | seed58(n - 1, newX)]
  end

  defp seed58(x_0) do
    {z0, x} = splitmix64_next(x_0)
    case (z0 &&& (1 <<< 58 - 1)) do
      0 ->
        seed58(x)
      z ->
        {z, x}
    end
  end

  defp seed64(0, _X) do
    []
  end

  defp seed64(n, x) do
    {z, newX} = seed64(x)
    [z | seed64(n - 1, newX)]
  end

  defp seed64(x_0) do
    {z, x} = (zX = splitmix64_next(x_0))
    cond do
      z === 0 ->
        seed64(x)
      true ->
        zX
    end
  end

  def splitmix64_next(x_0) do
    x = (x_0 + 11400714819323198485) &&& (1 <<< 64 - 1)
    z_0 = (x ^^^ (x >>> 30)) * 13787848793156543929 &&& (1 <<< 64 - 1)
    z_1 = (z_0 ^^^ (z_0 >>> 27)) * 10723151780598845931 &&& (1 <<< 64 - 1)
    {(z_1 ^^^ (z_1 >>> 31)) &&& (1 <<< 64 - 1), x}
  end

  defp polyjump({ss, rs} = sR, nextState, jumpConst) do
    ts = :lists.duplicate(length(ss) + length(rs), 0)
    polyjump(sR, nextState, jumpConst, ts)
  end

  defp polyjump(_SR, _NextState, [], ts) do
    {ts, []}
  end

  defp polyjump(sR, nextState, [j | js], ts) do
    polyjump(sR, nextState, js, ts, j)
  end

  defp polyjump(sR, nextState, js, ts, 1) do
    polyjump(sR, nextState, js, ts)
  end

  defp polyjump({ss, rs} = sR, nextState, js, ts, j)
      when j !== 0 do
    newSR = nextState.(sR)
    newJ = j >>> 1
    case (j &&& (1 <<< 1 - 1)) do
      0 ->
        polyjump(newSR, nextState, js, ts, newJ)
      1 ->
        polyjump(newSR, nextState, js, xorzip_sr(ts, ss, rs),
                   newJ)
    end
  end

  defp xorzip_sr([], [], :undefined) do
    []
  end

  defp xorzip_sr(ts, [], rs) do
    xorzip_sr(ts, :lists.reverse(rs), :undefined)
  end

  defp xorzip_sr([t | ts], [s | ss], rs) do
    [t ^^^ s | xorzip_sr(ts, ss, rs)]
  end

  def format_jumpconst58(string) do
    reOpts = [{:newline, :any}, {:capture, :all_but_first,
                                   :binary},
                                    :global]
    {:match, matches} = :re.run(string, '0x([a-zA-Z0-9]+)', reOpts)
    format_jumcons58_matches(:lists.reverse(matches), 0)
  end

  defp format_jumcons58_matches([], j) do
    format_jumpconst58_value(j)
  end

  defp format_jumcons58_matches([[bin] | matches], j) do
    newJ = j <<< 64 ||| :erlang.binary_to_integer(bin, 16)
    format_jumcons58_matches(matches, newJ)
  end

  defp format_jumpconst58_value(0) do
    :ok
  end

  defp format_jumpconst58_value(j) do
    :io.format('16#~s,~n',
                 [:erlang.integer_to_list(j &&& (1 <<< 58 - 1) ||| (1 <<< 58),
                                            16)])
    format_jumpconst58_value(j >>> 58)
  end

  defp get_52({%{bits: bits, next: next} = algHandler, s0}) do
    {int, s1} = next.(s0)
    {(1 <<< (bits - 51 - 1)) &&& int, int >>> (bits - 51),
       {algHandler, s1}}
  end

  defp get_52({%{next: next} = algHandler, s0}) do
    {int, s1} = next.(s0)
    {(1 <<< 51) &&& int, int &&& (1 <<< 51 - 1),
       {algHandler, s1}}
  end

  defp normal_s(0, sign, x0, state0) do
    {u0, s1} = uniform_s(state0)
    x = - 1 / 3.654152885361009 * :math.log(u0)
    {u1, s2} = uniform_s(s1)
    y = - :math.log(u1)
    case (y + y > x * x) do
      false ->
        normal_s(0, sign, x0, s2)
      true when sign === 0 ->
        {3.654152885361009 + x, s2}
      true ->
        {- 3.654152885361009 - x, s2}
    end
  end

  defp normal_s(idx, _Sign, x, state0) do
    fi2 = normal_fi(idx + 1)
    {u0, s1} = uniform_s(state0)
    case ((normal_fi(idx) - fi2) * u0 + fi2 < :math.exp(-
                                                        0.5 * x * x)) do
      true ->
        {x, s1}
      false ->
        normal_s(s1)
    end
  end

  defp normal_kiwi(indx) do
    :erlang.element(indx,
                      {{2104047571236786, 1.736725412160263e-15},
                         {0, 9.558660351455634e-17},
                         {1693657211986787, 1.2708704834810623e-16},
                         {1919380038271141, 1.4909740962495474e-16},
                         {2015384402196343, 1.6658733631586268e-16},
                         {2068365869448128, 1.8136120810119029e-16},
                         {2101878624052573, 1.9429720153135588e-16},
                         {2124958784102998, 2.0589500628482093e-16},
                         {2141808670795147, 2.1646860576895422e-16},
                         {2154644611568301, 2.2622940392218116e-16},
                         {2164744887587275, 2.353271891404589e-16},
                         {2172897953696594, 2.438723455742877e-16},
                         {2179616279372365, 2.5194879829274225e-16},
                         {2185247251868649, 2.5962199772528103e-16},
                         {2190034623107822, 2.6694407473648285e-16},
                         {2194154434521197, 2.7395729685142446e-16},
                         {2197736978774660, 2.8069646002484804e-16},
                         {2200880740891961, 2.871905890411393e-16},
                         {2203661538010620, 2.9346417484728883e-16},
                         {2206138681109102, 2.9953809336782113e-16},
                         {2208359231806599, 3.054303000719244e-16},
                         {2210361007258210, 3.111563633892157e-16},
                         {2212174742388539, 3.1672988018581815e-16},
                         {2213825672704646, 3.2216280350549905e-16},
                         {2215334711002614, 3.274657040793975e-16},
                         {2216719334487595, 3.326479811684171e-16},
                         {2217994262139172, 3.377180341735323e-16},
                         {2219171977965032, 3.4268340353119356e-16},
                         {2220263139538712, 3.475508873172976e-16},
                         {2221276900117330, 3.523266384600203e-16},
                         {2222221164932930, 3.5701624633953494e-16},
                         {2223102796829069, 3.616248057159834e-16},
                         {2223927782546658, 3.661569752965354e-16},
                         {2224701368170060, 3.7061702777236077e-16},
                         {2225428170204312, 3.75008892787478e-16},
                         {2226112267248242, 3.7933619401549554e-16},
                         {2226757276105256, 3.836022812967728e-16},
                         {2227366415328399, 3.8781025861250247e-16},
                         {2227942558554684, 3.919630085325768e-16},
                         {2228488279492521, 3.9606321366256378e-16},
                         {2229005890047222, 4.001133755254669e-16},
                         {2229497472775193, 4.041158312414333e-16},
                         {2229964908627060, 4.080727683096045e-16},
                         {2230409900758597, 4.119862377480744e-16},
                         {2230833995044585, 4.1585816580828064e-16},
                         {2231238597816133, 4.1969036444740733e-16},
                         {2231624991250191, 4.234845407152071e-16},
                         {2231994346765928, 4.272423051889976e-16},
                         {2232347736722750, 4.309651795716294e-16},
                         {2232686144665934, 4.346546035512876e-16},
                         {2233010474325959, 4.383119410085457e-16},
                         {2233321557544881, 4.4193848564470665e-16},
                         {2233620161276071, 4.455354660957914e-16},
                         {2233906993781271, 4.491040505882875e-16},
                         {2234182710130335, 4.52645351185714e-16},
                         {2234447917093496, 4.561604276690038e-16},
                         {2234703177503020, 4.596502910884941e-16},
                         {2234949014150181, 4.631159070208165e-16},
                         {2235185913274316, 4.665581985600875e-16},
                         {2235414327692884, 4.699780490694195e-16},
                         {2235634679614920, 4.733763047158324e-16},
                         {2235847363174595, 4.767537768090853e-16},
                         {2236052746716837, 4.8011124396270155e-16},
                         {2236251174862869, 4.834494540935008e-16},
                         {2236442970379967, 4.867691262742209e-16},
                         {2236628435876762, 4.900709524522994e-16},
                         {2236807855342765, 4.933555990465414e-16},
                         {2236981495548562, 4.966237084322178e-16},
                         {2237149607321147, 4.998759003240909e-16},
                         {2237312426707209, 5.031127730659319e-16},
                         {2237470176035652, 5.0633490483427195e-16},
                         {2237623064889403, 5.095428547633892e-16},
                         {2237771290995388, 5.127371639978797e-16},
                         {2237915041040597, 5.159183566785736e-16},
                         {2238054491421305, 5.190869408670343e-16},
                         {2238189808931712, 5.222434094134042e-16},
                         {2238321151397660, 5.253882407719454e-16},
                         {2238448668260432, 5.285218997682382e-16},
                         {2238572501115169, 5.316448383216618e-16},
                         {2238692784207942, 5.34757496126473e-16},
                         {2238809644895133, 5.378603012945235e-16},
                         {2238923204068402, 5.409536709623993e-16},
                         {2239033576548190, 5.440380118655467e-16},
                         {2239140871448443, 5.471137208817361e-16},
                         {2239245192514958, 5.501811855460336e-16},
                         {2239346638439541, 5.532407845392784e-16},
                         {2239445303151952, 5.56292888151909e-16},
                         {2239541276091442, 5.593378587248462e-16},
                         {2239634642459498, 5.623760510690043e-16},
                         {2239725483455293, 5.65407812864896e-16},
                         {2239813876495186, 5.684334850436814e-16},
                         {2239899895417494, 5.714534021509204e-16},
                         {2239983610673676, 5.744678926941961e-16},
                         {2240065089506935, 5.774772794756965e-16},
                         {2240144396119183, 5.804818799107686e-16},
                         {2240221591827230, 5.834820063333892e-16},
                         {2240296735208969, 5.864779662894365e-16},
                         {2240369882240293, 5.894700628185872e-16},
                         {2240441086423386, 5.924585947256134e-16},
                         {2240510398907004, 5.95443856841806e-16},
                         {2240577868599305, 5.984261402772028e-16},
                         {2240643542273726, 6.014057326642664e-16},
                         {2240707464668391, 6.043829183936125e-16},
                         {2240769678579486, 6.073579788423606e-16},
                         {2240830224948980, 6.103311925956439e-16},
                         {2240889142947082, 6.133028356617911e-16},
                         {2240946470049769, 6.162731816816596e-16},
                         {2241002242111691, 6.192425021325847e-16},
                         {2241056493434746, 6.222110665273788e-16},
                         {2241109256832602, 6.251791426088e-16},
                         {2241160563691400, 6.281469965398895e-16},
                         {2241210444026879, 6.311148930905604e-16},
                         {2241258926538122, 6.34083095820806e-16},
                         {2241306038658137, 6.370518672608815e-16},
                         {2241351806601435, 6.400214690888025e-16},
                         {2241396255408788, 6.429921623054896e-16},
                         {2241439408989313, 6.459642074078832e-16},
                         {2241481290160038, 6.489378645603397e-16},
                         {2241521920683062, 6.519133937646159e-16},
                         {2241561321300462, 6.548910550287415e-16},
                         {2241599511767028, 6.578711085350741e-16},
                         {2241636510880960, 6.608538148078259e-16},
                         {2241672336512612, 6.638394348803506e-16},
                         {2241707005631362, 6.668282304624746e-16},
                         {2241740534330713, 6.698204641081558e-16},
                         {2241772937851689, 6.728163993837531e-16},
                         {2241804230604585, 6.758163010371901e-16},
                         {2241834426189161, 6.78820435168298e-16},
                         {2241863537413311, 6.818290694006254e-16},
                         {2241891576310281, 6.848424730550038e-16},
                         {2241918554154466, 6.878609173251664e-16},
                         {2241944481475843, 6.908846754557169e-16},
                         {2241969368073071, 6.939140229227569e-16},
                         {2241993223025298, 6.969492376174829e-16},
                         {2242016054702685, 6.999906000330764e-16},
                         {2242037870775710, 7.030383934552151e-16},
                         {2242058678223225, 7.060929041565482e-16},
                         {2242078483339331, 7.091544215954873e-16},
                         {2242097291739040, 7.122232386196779e-16},
                         {2242115108362774, 7.152996516745303e-16},
                         {2242131937479672, 7.183839610172063e-16},
                         {2242147782689725, 7.214764709364707e-16},
                         {2242162646924736, 7.245774899788387e-16},
                         {2242176532448092, 7.276873311814693e-16},
                         {2242189440853337, 7.308063123122743e-16},
                         {2242201373061537, 7.339347561177405e-16},
                         {2242212329317416, 7.370729905789831e-16},
                         {2242222309184237, 7.4022134917658e-16},
                         {2242231311537397, 7.433801711647648e-16},
                         {2242239334556717, 7.465498018555889e-16},
                         {2242246375717369, 7.497305929136979e-16},
                         {2242252431779415, 7.529229026624058e-16},
                         {2242257498775893, 7.561270964017922e-16},
                         {2242261571999416, 7.5934354673958895e-16},
                         {2242264645987196, 7.625726339356756e-16},
                         {2242266714504453, 7.658147462610487e-16},
                         {2242267770526109, 7.690702803721919e-16},
                         {2242267806216711, 7.723396417018299e-16},
                         {2242266812908462, 7.756232448671174e-16},
                         {2242264781077289, 7.789215140963852e-16},
                         {2242261700316818, 7.822348836756411e-16},
                         {2242257559310145, 7.855637984161084e-16},
                         {2242252345799276, 7.889087141441755e-16},
                         {2242246046552082, 7.922700982152271e-16},
                         {2242238647326615, 7.956484300529366e-16},
                         {2242230132832625, 7.99044201715713e-16},
                         {2242220486690076, 8.024579184921259e-16},
                         {2242209691384458, 8.058900995272657e-16},
                         {2242197728218684, 8.093412784821501e-16},
                         {2242184577261310, 8.128120042284501e-16},
                         {2242170217290819, 8.163028415809877e-16},
                         {2242154625735679, 8.198143720706533e-16},
                         {2242137778609839, 8.23347194760605e-16},
                         {2242119650443327, 8.26901927108847e-16},
                         {2242100214207556, 8.304792058805374e-16},
                         {2242079441234906, 8.340796881136629e-16},
                         {2242057301132135, 8.377040521420222e-16},
                         {2242033761687079, 8.413529986798028e-16},
                         {2242008788768107, 8.450272519724097e-16},
                         {2241982346215682, 8.487275610186155e-16},
                         {2241954395725356, 8.524547008695596e-16},
                         {2241924896721443, 8.562094740106233e-16},
                         {2241893806220517, 8.599927118327665e-16},
                         {2241861078683830, 8.638052762005259e-16},
                         {2241826665857598, 8.676480611245582e-16},
                         {2241790516600041, 8.715219945473698e-16},
                         {2241752576693881, 8.754280402517175e-16},
                         {2241712788642916, 8.793671999021043e-16},
                         {2241671091451078, 8.833405152308408e-16},
                         {2241627420382235, 8.873490703813135e-16},
                         {2241581706698773, 8.913939944224086e-16},
                         {2241533877376767, 8.954764640495068e-16},
                         {2241483854795281, 8.9959770648911e-16},
                         {2241431556397035, 9.037590026260118e-16},
                         {2241376894317345, 9.079616903740068e-16},
                         {2241319774977817, 9.122071683134846e-16},
                         {2241260098640860, 9.164968996219135e-16},
                         {2241197758920538, 9.208324163262308e-16},
                         {2241132642244704, 9.252153239095693e-16},
                         {2241064627262652, 9.296473063086417e-16},
                         {2240993584191742, 9.341301313425265e-16},
                         {2240919374095536, 9.38665656618666e-16},
                         {2240841848084890, 9.432558359676707e-16},
                         {2240760846432232, 9.479027264651738e-16},
                         {2240676197587784, 9.526084961066279e-16},
                         {2240587717084782, 9.57375432209745e-16},
                         {2240495206318753, 9.622059506294838e-16},
                         {2240398451183567, 9.671026058823054e-16},
                         {2240297220544165, 9.720681022901626e-16},
                         {2240191264522612, 9.771053062707209e-16},
                         {2240080312570155, 9.822172599190541e-16},
                         {2239964071293331, 9.874071960480671e-16},
                         {2239842221996530, 9.926785548807976e-16},
                         {2239714417896699, 9.980350026183645e-16},
                         {2239580280957725, 1.003480452143618e-15},
                         {2239439398282193, 1.0090190861637457e-15},
                         {2239291317986196, 1.0146553831467086e-15},
                         {2239135544468203, 1.0203941464683124e-15},
                         {2238971532964979, 1.0262405372613567e-15},
                         {2238798683265269, 1.0322001115486456e-15},
                         {2238616332424351, 1.03827886235154e-15},
                         {2238423746288095, 1.044483267600047e-15},
                         {2238220109591890, 1.0508203448355195e-15},
                         {2238004514345216, 1.057297713900989e-15},
                         {2237775946143212, 1.06392366906768e-15},
                         {2237533267957822, 1.0707072623632994e-15},
                         {2237275200846753, 1.0776584002668106e-15},
                         {2237000300869952, 1.0847879564403425e-15},
                         {2236706931309099, 1.0921079038149563e-15},
                         {2236393229029147, 1.0996314701785628e-15},
                         {2236057063479501, 1.1073733224935752e-15},
                         {2235695986373246, 1.1153497865853155e-15},
                         {2235307169458859, 1.1235791107110833e-15},
                         {2234887326941578, 1.1320817840164846e-15},
                         {2234432617919447, 1.140880924258278e-15},
                         {2233938522519765, 1.1500027537839792e-15},
                         {2233399683022677, 1.159477189144919e-15},
                         {2232809697779198, 1.169338578691096e-15},
                         {2232160850599817, 1.17962663529558e-15},
                         {2231443750584641, 1.190387629928289e-15},
                         {2230646845562170, 1.2016759392543819e-15},
                         {2229755753817986, 1.2135560818666897e-15},
                         {2228752329126533, 1.2261054417450561e-15},
                         {2227613325162504, 1.2394179789163251e-15},
                         {2226308442121174, 1.2536093926602567e-15},
                         {2224797391720399, 1.268824481425501e-15},
                         {2223025347823832, 1.2852479319096109e-15},
                         {2220915633329809, 1.3031206634689985e-15},
                         {2218357446087030, 1.3227655770195326e-15},
                         {2215184158448668, 1.3446300925011171e-15},
                         {2211132412537369, 1.3693606835128518e-15},
                         {2205758503851065, 1.397943667277524e-15},
                         {2198248265654987, 1.4319989869661328e-15},
                         {2186916352102141, 1.4744848603597596e-15},
                         {2167562552481814, 1.5317872741611144e-15},
                         {2125549880839716, 1.6227698675312968e-15}})
  end

  defp normal_fi(indx) do
    :erlang.element(indx,
                      {1.0, 0.9771017012676708, 0.959879091800106,
                         0.9451989534422991, 0.9320600759592299,
                         0.9199915050393465, 0.9087264400521303,
                         0.898095921898343, 0.8879846607558328,
                         0.8783096558089168, 0.8690086880368565,
                         0.8600336211963311, 0.8513462584586775,
                         0.8429156531122037, 0.834716292986883,
                         0.8267268339462209, 0.8189291916037019,
                         0.8113078743126557, 0.8038494831709638,
                         0.7965423304229584, 0.789376143566024,
                         0.782341832654802, 0.7754313049811866,
                         0.7686373157984857, 0.7619533468367948,
                         0.7553735065070957, 0.7488924472191564,
                         0.7425052963401506, 0.7362075981268621,
                         0.7299952645614757, 0.7238645334686297,
                         0.7178119326307215, 0.711834248878248,
                         0.7059285013327538, 0.7000919181365112,
                         0.6943219161261163, 0.6886160830046714,
                         0.6829721616449943, 0.6773880362187731,
                         0.6718617198970817, 0.6663913439087498,
                         0.6609751477766628, 0.6556114705796969,
                         0.6502987431108164, 0.645035480820822,
                         0.6398202774530561, 0.6346517992876233,
                         0.6295287799248362, 0.6244500155470261,
                         0.619414360605834, 0.6144207238889134,
                         0.6094680649257731, 0.6045553906974673,
                         0.5996817526191248, 0.5948462437679869,
                         0.5900479963328255, 0.5852861792633709,
                         0.5805599961007903, 0.5758686829723532,
                         0.5712115067352527, 0.5665877632561639,
                         0.5619967758145239, 0.5574378936187655,
                         0.5529104904258318, 0.5484139632552654,
                         0.5439477311900258, 0.5395112342569516,
                         0.5351039323804572, 0.5307253044036615,
                         0.526374847171684, 0.5220520746723214,
                         0.5177565172297559, 0.5134877207473265,
                         0.5092452459957476, 0.5050286679434679,
                         0.5008375751261483, 0.4966715690524893,
                         0.49253026364386815, 0.4884132847054576,
                         0.4843202694266829, 0.4802508659090464,
                         0.4762047327195055, 0.47218153846772976,
                         0.4681809614056932, 0.4642026890481739,
                         0.4602464178128425, 0.4563118526787161,
                         0.45239870686184824, 0.44850670150720273,
                         0.4446355653957391, 0.44078503466580377,
                         0.43695485254798533, 0.4331447691126521,
                         0.42935454102944126, 0.4255839313380218,
                         0.42183270922949573, 0.41810064983784795,
                         0.4143875340408909, 0.410693148270188,
                         0.40701728432947315, 0.4033597392211143,
                         0.399720314980197, 0.39609881851583223,
                         0.3924950614593154, 0.38890886001878855,
                         0.38534003484007706, 0.38178841087339344,
                         0.37825381724561896, 0.37473608713789086,
                         0.3712350576682392, 0.36775056977903225,
                         0.3642824681290037, 0.36083060098964775,
                         0.3573948201457802, 0.35397498080007656,
                         0.3505709414814059, 0.3471825639567935,
                         0.34380971314685055, 0.34045225704452164,
                         0.3371100666370059, 0.33378301583071823,
                         0.3304709813791634, 0.3271738428136013,
                         0.32389148237639104, 0.3206237849569053,
                         0.3173706380299135, 0.31413193159633707,
                         0.31090755812628634, 0.3076974125042919,
                         0.3045013919766498, 0.3013193961008029,
                         0.2981513266966853, 0.29499708779996164,
                         0.291856585617095, 0.2887297284821827,
                         0.2856164268155016, 0.2825165930837074,
                         0.2794301417616377, 0.2763569892956681,
                         0.2732970540685769, 0.2702502563658752,
                         0.26721651834356114, 0.2641957639972608,
                         0.2611879191327208, 0.2581929113376189,
                         0.2552106699546617, 0.2522411260559419,
                         0.24928421241852824, 0.24633986350126363,
                         0.24340801542275012, 0.2404886059405004,
                         0.23758157443123795, 0.2346868618723299,
                         0.23180441082433859, 0.22893416541468023,
                         0.2260760713223802, 0.22323007576391746,
                         0.22039612748015194, 0.21757417672433113,
                         0.21476417525117358, 0.21196607630703015,
                         0.209179834621125, 0.20640540639788071,
                         0.20364274931033485, 0.20089182249465656,
                         0.1981525865457751, 0.19542500351413428,
                         0.19270903690358912, 0.19000465167046496,
                         0.18731181422380025, 0.18463049242679927,
                         0.18196065559952254, 0.17930227452284767,
                         0.176655321443735, 0.17401977008183875,
                         0.17139559563750595, 0.1687827748012115,
                         0.16618128576448205, 0.1635911082323657,
                         0.16101222343751107, 0.1584446141559243,
                         0.1558882647244792, 0.15334316106026283,
                         0.15080929068184568, 0.14828664273257453,
                         0.14577520800599403, 0.1432749789735134,
                         0.1407859498144447, 0.1383081164485507,
                         0.13584147657125373, 0.13338602969166913,
                         0.1309417771736443, 0.12850872227999952,
                         0.12608687022018586, 0.12367622820159654,
                         0.12127680548479021, 0.11888861344290998,
                         0.1165116656256108, 0.11414597782783835,
                         0.111791568163838, 0.10944845714681163,
                         0.10711666777468364, 0.1047962256224869,
                         0.10248715894193508, 0.10018949876880981,
                         0.09790327903886228, 0.09562853671300882,
                         0.09336531191269086, 0.09111364806637363,
                         0.08887359206827579, 0.08664519445055796,
                         0.08442850957035337, 0.08222359581320286,
                         0.08003051581466306, 0.07784933670209604,
                         0.07568013035892707, 0.07352297371398127,
                         0.07137794905889037, 0.06924514439700677,
                         0.0671246538277885, 0.06501657797124284,
                         0.06292102443775811, 0.060838108349539864,
                         0.05876795292093376, 0.0567106901062029,
                         0.054666461324888914, 0.052635418276792176,
                         0.05061772386094776, 0.04861355321586852,
                         0.04662309490193037, 0.04464655225129444,
                         0.04268414491647443, 0.04073611065594093,
                         0.03880270740452611, 0.036884215688567284,
                         0.034980941461716084, 0.03309321945857852,
                         0.031221417191920245, 0.029365939758133314,
                         0.027527235669603082, 0.025705804008548896,
                         0.023902203305795882, 0.022117062707308864,
                         0.020351096230044517, 0.018605121275724643,
                         0.016880083152543166, 0.015177088307935325,
                         0.01349745060173988, 0.011842757857907888,
                         0.010214971439701471, 0.008616582769398732,
                         0.007050875471373227, 0.005522403299250997,
                         0.0040379725933630305, 0.0026090727461021627,
                         0.0012602859304985975})
  end

  def bc64(v) do
    bc(v, 1 <<< (64 - 1), 64)
  end

  defp bc(v, b, n) when b <= v do
    n
  end

  defp bc(v, b, n) do
    bc(v, b >>> 1, n - 1)
  end

  def make_float(s, e, m) do
    <<f :: float>> = <<s :: size(1), e :: size(11),
                         m :: size(52)>>
    f
  end

  def float2str(n) do
    <<s :: size(1), e :: size(11),
        m :: size(52)>> = <<:erlang.float(n) :: float>>
    :lists.flatten(:io_lib.format('~c~c.~13.16.0bE~b',
                                    [case (s) do
                                       1 ->
                                         ?-
                                       0 ->
                                         ?+
                                     end,
                                         case (e) do
                                           0 ->
                                             ?0
                                           _ ->
                                             ?1
                                         end,
                                             m, e - 1023]))
  end

end