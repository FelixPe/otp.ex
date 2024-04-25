defmodule :m_erl_features do
  use Bitwise
  defp feature_specs() do
    %{maybe_expr:
      %{short: 'Value based error handling (EEP49)', description: 'Implementation of the maybe expression proposed in EEP49 -- Value based error handling.', status: :experimental,
          experimental: 25, keywords: [:maybe, :else],
          type: :extension}}
  end

  def all() do
    map = (case (:persistent_term.get({:erl_features,
                                         :feature_specs},
                                        :none)) do
             :none ->
               init_specs()
             m ->
               m
           end)
    :lists.sort(:maps.keys(map))
  end

  def configurable() do
    for ftr <- all(),
          :lists.member(:maps.get(:status, info(ftr)),
                          [:experimental, :approved]) do
      ftr
    end
  end

  defp is_valid(ftr) do
    :lists.member(ftr, all())
  end

  defp is_configurable(ftr) do
    :lists.member(ftr, configurable())
  end

  def short(feature) do
    %{short: short, status: status} = (info = info(feature))
    %{^status => release} = info
    :io_lib.format('~-40s ~-12s (~p)', [short, status, release])
  end

  def long(feature) do
    %{short: short, description: description,
        status: status, keywords: keywords,
        type: type} = (info = info(feature))
    statusFmt = '  ~-10s ~-12s (~p)\n'
    history = (for {t, s, r} <- history(status, info) do
                 :io_lib.format(statusFmt, [t, s, r])
               end)
    keywordsStrs = (cond do
                      keywords == [] ->
                        ''
                      true ->
                        :io_lib.format('  ~-10s ~p\n', ['Keywords', keywords])
                    end)
    lines = [{'~s - ~s\n', [feature, short]}, {'  ~-10s ~s\n', ['Type', type]}, {'~s',
                                                       [history]},
                                                        {'~s', [keywordsStrs]}, {'\n~s\n',
                                                                                [nqTeX(description)]}]
    for {fStr, args} <- lines do
      :io_lib.format(fStr, args)
    end
  end

  defp history(current, info) do
    g = fn key, s ->
             case (:maps.find(key, info)) do
               :error ->
                 []
               {:ok, r} ->
                 [{s, key, r}]
             end
        end
    f = fn key ->
             g.(key, '')
        end
    history = (case (current) do
                 :experimental ->
                   []
                 :rejected ->
                   f.(:experimental)
                 :approved ->
                   f.(:experimental)
                 :permanent ->
                   f.(:approved) ++ f.(:experimental)
               end)
    g.(current, 'Status') ++ history
  end

  defp nqTeX(string) do
    words = :string.tokens(string, ' ')
    withLens = :lists.map(fn w ->
                               {w, length(w)}
                          end,
                            words)
    adjust(withLens)
  end

  defp adjust(wLs) do
    adjust(0, wLs, [])
  end

  defp adjust(_, [], ws) do
    :lists.reverse(tl(ws))
  end

  defp adjust(col, [{w, l} | wLs], ws) do
    case (col + l > 72) do
      true ->
        :lists.reverse(['\n' | tl(ws)]) ++ adjust(l + 1, wLs,
                                                 [' ', w])
      false ->
        adjust(col + l + 1, wLs, [' ', w | ws])
    end
  end

  def info(feature) do
    case (is_valid(feature)) do
      false ->
        error(:invalid_feature, [feature],
                [{:error_info,
                    %{module: :erl_features, cause: %{1 => 'unknown feature'}}}])
      true ->
        :ok
    end
    map = :persistent_term.get({:erl_features,
                                  :feature_specs})
    :maps.get(feature, map)
  end

  def keywords(ftr) do
    case (is_valid(ftr)) do
      false ->
        error(:invalid_feature, [ftr],
                [{:error_info,
                    %{module: :erl_features, cause: %{1 => 'unknown feature'}}}])
      true ->
        :ok
    end
    %{keywords: keywords} = info(ftr)
    keywords
  end

  defp keywords(ftr, map) do
    :maps.get(:keywords, :maps.get(ftr, map))
  end

  def keyword_fun(opts, keywordFun) do
    isFtr = fn {:feature, _, :enable} ->
                 true
               {:feature, _, :disable} ->
                 true
               _ ->
                 false
            end
    featureOps = :lists.filter(isFtr, opts)
    {addFeatures, delFeatures,
       rawFtrs} = collect_features(featureOps)
    case (configurable_features(rawFtrs)) do
      :ok ->
        {:ok, fun} = add_features_fun(addFeatures, keywordFun)
        {:ok, funX} = remove_features_fun(delFeatures, fun)
        {:ok, {addFeatures -- delFeatures, funX}}
      {:error, _} = error ->
        error
    end
  end

  def keyword_fun(ind, feature, ftrs, keywordFun) do
    case (is_configurable(feature)) do
      true ->
        case (ind) do
          :enable ->
            newFtrs = (case (:lists.member(feature, ftrs)) do
                         true ->
                           ftrs
                         false ->
                           [feature | ftrs]
                       end)
            {:ok, {newFtrs, add_feature_fun(feature, keywordFun)}}
          :disable ->
            {:ok,
               {ftrs -- [feature],
                  remove_feature_fun(feature, keywordFun)}}
        end
      false ->
        error = (case (is_valid(feature)) do
                   true ->
                     :not_configurable
                   false ->
                     :invalid_features
                 end)
        {:error, {:erl_features, {error, [feature]}}}
    end
  end

  defp add_feature_fun(feature, f) do
    words = keywords(feature)
    fn word ->
         :lists.member(word, words) or f.(word)
    end
  end

  defp remove_feature_fun(feature, f) do
    words = keywords(feature)
    fn word ->
         case (:lists.member(word, words)) do
           true ->
             false
           false ->
             f.(word)
         end
    end
  end

  defp add_features_fun(features, f) do
    {:ok, :lists.foldl(&add_feature_fun/2, f, features)}
  end

  defp remove_features_fun(features, f) do
    {:ok, :lists.foldl(&remove_feature_fun/2, f, features)}
  end

  defp configurable_features(features) do
    case (:lists.all(&is_configurable/1, features)) do
      true ->
        :ok
      false ->
        feature_error(features)
    end
  end

  defp feature_error(features) do
    isInvalid = fn ftr ->
                     not is_valid(ftr)
                end
    isNonConfig = fn ftr ->
                       is_valid(ftr) and not is_configurable(ftr)
                  end
    invalid = :lists.filter(isInvalid, features)
    nonConfig = :lists.filter(isNonConfig, features)
    {error, culprits} = (case ({invalid, nonConfig}) do
                           {[], nC} ->
                             {:not_configurable, nC}
                           {nV, []} ->
                             {:invalid_features, nV}
                           {nV, nC} ->
                             {:incorrect_features, nV ++ nC}
                         end)
    {:error, {:erl_features, {error, culprits}}}
  end

  def format_error(reason, [{_M, _F, _Args, info} | _St]) do
    errorInfo = :proplists.get_value(:error_info, info, %{})
    errorMap = :maps.get(:cause, errorInfo)
    Map.put(errorMap, :reason,
                        :io_lib.format('~p: ~p', [:erl_features, reason]))
  end

  def format_error({error, features}) do
    fmt = fn f
          [ftr] ->
            :io_lib.fwrite('\'~p\'', [ftr])
          [ftr1, ftr2] ->
            :io_lib.fwrite('\'~p\' and \'~p\'', [ftr1, ftr2])
          [ftr | ftrs] ->
            :io_lib.fwrite('\'~p\', ~s', [ftr, f.(ftrs)])
          end
    fmtStr = (case ({error, features}) do
                {:invalid_features, [_]} ->
                  'the feature ~s does not exist.'
                {:invalid_features, _} ->
                  'the features ~s do not exist.'
                {:not_configurable, [_]} ->
                  'the feature ~s is not configurable.'
                {:not_configurable, _} ->
                  'the features ~s are not configurable.'
                {:incorrect_features, _} ->
                  'the features ~s do not exist or are not configurable.'
              end)
    :io_lib.fwrite(fmtStr, [fmt.(features)])
  end

  defp init_features() do
    map = init_specs()
    :persistent_term.put({:erl_features, :enabled_features},
                           [])
    :persistent_term.put({:erl_features, :keywords}, [])
    rawOps = :lists.filter(fn {tag, _} ->
                                tag == :"enable-feature" or tag == :"disable-feature"
                              _ ->
                                false
                           end,
                             :init.get_arguments())
    cnv = fn :"enable-feature" ->
               :enable
             :"disable-feature" ->
               :disable
          end
    featureOps = :lists.append(:lists.map(fn {tag,
                                                strings} ->
                                               :lists.map(fn s ->
                                                               {tag, s}
                                                          end,
                                                            strings)
                                          end,
                                            rawOps))
    f = fn {tag, string} ->
             try do
               atom = :erlang.list_to_atom(string)
               case (is_configurable(atom)) do
                 true ->
                   {true, {:feature, atom, cnv.(tag)}}
                 false when atom == :all ->
                   {true, {:feature, atom, cnv.(tag)}}
                 false ->
                   false
               end
             catch
               _ ->
                 false
             end
        end
    fOps = :lists.filtermap(f, featureOps)
    {features, _, _} = collect_features(fOps)
    {enabled0, keywords} = :lists.foldl(fn ftr,
                                             {ftrs, keys} ->
                                             case (:lists.member(ftr, ftrs)) do
                                               true ->
                                                 {ftrs, keys}
                                               false ->
                                                 {[ftr | ftrs],
                                                    keywords(ftr, map) ++ keys}
                                             end
                                        end,
                                          {[], []}, features)
    enabled = :lists.uniq(enabled0)
    enabled_features(enabled)
    set_keywords(keywords)
    :persistent_term.put({:erl_features, :init_done}, true)
    :ok
  end

  defp init_specs() do
    specs = (case (:os.getenv('OTP_TEST_FEATURES')) do
               'true' ->
                 test_features()
               _ ->
                 feature_specs()
             end)
    :persistent_term.put({:erl_features, :feature_specs},
                           specs)
    specs
  end

  defp ensure_init() do
    case (:persistent_term.get({:erl_features, :init_done},
                                 false)) do
      true ->
        :ok
      false ->
        init_features()
    end
  end

  def enabled() do
    ensure_init()
    :persistent_term.get({:erl_features, :enabled_features})
  end

  defp enabled_features(ftrs) do
    :persistent_term.put({:erl_features, :enabled_features},
                           ftrs)
  end

  def keywords() do
    ensure_init()
    :persistent_term.get({:erl_features, :keywords})
  end

  defp set_keywords(words) do
    :persistent_term.put({:erl_features, :keywords}, words)
  end

  def used(module) when is_atom(module) do
    case (:code.get_object_code(module)) do
      :error ->
        :not_found
      {_Mod, bin, _Fname} ->
        features_in(bin)
    end
  end

  def used(fName) when is_list(fName) do
    features_in(fName)
  end

  defp features_in(nameOrBin) do
    case (:beam_lib.chunks(nameOrBin, ['Meta'],
                             [:allow_missing_chunks])) do
      {:ok, {_, [{_, :missing_chunk}]}} ->
        []
      {:ok, {_, [{_, meta}]}} ->
        metaData = :erlang.binary_to_term(meta)
        :proplists.get_value(:enabled_features, metaData, [])
      _ ->
        :not_found
    end
  end

  defp collect_features(fOps) do
    enabled = (for ftr <- all(),
                     :maps.get(:status, info(ftr)) == :approved do
                 ftr
               end)
    collect_features(fOps, enabled, [], [])
  end

  defp collect_features([], add, del, raw) do
    {add, del, raw}
  end

  defp collect_features([{:feature, :all, :enable} | fOps], add, _Del,
            raw) do
    all = configurable()
    add1 = :lists.foldl(&add_ftr/2, add, all)
    collect_features(fOps, add1, [], raw)
  end

  defp collect_features([{:feature, feature, :enable} | fOps], add, del,
            raw) do
    collect_features(fOps, add_ftr(feature, add),
                       del -- [feature], raw ++ [feature])
  end

  defp collect_features([{:feature, :all, :disable} | fOps], _Add, del,
            raw) do
    all = configurable()
    collect_features(fOps, [], del -- all, raw)
  end

  defp collect_features([{:feature, feature, :disable} | fOps], add,
            del, raw) do
    collect_features(fOps, add -- [feature],
                       add_ftr(feature, del), raw ++ [feature])
  end

  defp add_ftr(f, []) do
    [f]
  end

  defp add_ftr(f, [f | _] = fs) do
    fs
  end

  defp add_ftr(f, [f0 | fs]) do
    [f0 | add_ftr(f, fs)]
  end

  defp test_features() do
    %{experimental_ftr_1:
      %{short: 'Experimental test feature #1', description: 'Test feature in the experimental state. It is disabled by default, but can be enabled.', status: :experimental,
          experimental: 24, keywords: [:ifn], type: :extension},
        experimental_ftr_2:
        %{short: 'Experimental test features #2', description: 'Test feature in experimental state. It is disabled by default, but can be enabled.', status: :experimental,
            experimental: 25, keywords: [:while, :until],
            type: :extension},
        approved_ftr_1:
        %{short: 'Approved test feature #1', description: 'Test feature in the approved state.  It is on by default and can be disabled.', status: :approved,
            experimental: 24, approved: 25, keywords: [],
            type: :extension},
        approved_ftr_2:
        %{short: 'Approved test feature #2', description: 'Test feature in the approved state. It is enabled by default, but can still be disabled.', status: :approved,
            experimental: 24, approved: 25, keywords: [:unless],
            type: :extension},
        permanent_ftr:
        %{short: 'Permanent test feature', description: 'Test feature in the permanent state.  This means it is on by default and cannot be disabled.  It is now a permanent part of Erlang/OTP.', status: :permanent,
            experimental: 17, approved: 18, permanent: 19,
            keywords: [], type: :extension},
        rejected_ftr:
        %{short: 'Rejected test feature.', description: 'Test feature existing only to end up as rejected. It is not available and cannot be enabled. This should be the only trace of it', status: :rejected,
            experimental: 24, rejected: 25,
            keywords: [:inline, :return, :set], type: :extension}}
  end

end