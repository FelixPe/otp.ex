defmodule :m_pubkey_policy_tree do
  use Bitwise
  require Record

  Record.defrecord(:r_SubjectPublicKeyInfoAlgorithm, :SubjectPublicKeyInfoAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_path_validation_state, :path_validation_state,
    valid_policy_tree: :undefined,
    user_initial_policy_set: :undefined,
    explicit_policy: :undefined,
    inhibit_any_policy: :undefined,
    inhibit_policy_mapping: :undefined,
    policy_mapping_ext: :undefined,
    policy_constraint_ext: :undefined,
    policy_inhibitany_ext: :undefined,
    policy_ext_present: :undefined,
    policy_ext_any: :undefined,
    current_any_policy_qualifiers: :undefined,
    cert_num: :undefined,
    last_cert: false,
    permitted_subtrees: :no_constraints,
    excluded_subtrees: [],
    working_public_key_algorithm: :undefined,
    working_public_key: :undefined,
    working_public_key_parameters: :undefined,
    working_issuer_name: :undefined,
    max_path_length: :undefined,
    verify_fun: :undefined,
    user_state: :undefined
  )

  Record.defrecord(:r_revoke_state, :revoke_state,
    reasons_mask: :undefined,
    cert_status: :undefined,
    interim_reasons_mask: :undefined,
    valid_ext: :undefined,
    details: :undefined
  )

  Record.defrecord(:r_ECPoint, :ECPoint, point: :undefined)

  Record.defrecord(:r_cert, :cert,
    der: :undefined,
    otp: :undefined
  )

  def add_leaves({parent, []}, leafFun) do
    {parent, leafFun.(parent)}
  end

  def add_leaves(tree, leafFun0) do
    leafFun = fn leaf ->
      newLeaves = leafFun0.(leaf)
      {leaf, newLeaves}
    end

    map_leaves(tree, leafFun)
  end

  def add_leaf_siblings(
        {parent, [{_, _} | _] = childNodes},
        siblingFun
      ) do
    {parent,
     :lists.map(
       fn childNode ->
         add_leaf_siblings(childNode, siblingFun)
       end,
       childNodes
     )}
  end

  def add_leaf_siblings({parent, leaves} = node, siblingFun) do
    case siblingFun.(parent) do
      :no_sibling ->
        node

      siblings ->
        {parent, leaves ++ siblings}
    end
  end

  def all_leaves({}) do
    []
  end

  def all_leaves({_, [{_, _} | _] = childNodes}) do
    :lists.flatmap(
      fn childNode ->
        all_leaves(childNode)
      end,
      childNodes
    )
  end

  def all_leaves({_, leaves}) do
    leaves
  end

  def constrained_policy_node_set({}) do
    []
  end

  def constrained_policy_node_set(tree) do
    case any_leaves(tree) do
      [] ->
        constrain(tree)

      anyLeaves ->
        anyLeaves
    end
  end

  def empty() do
    {}
  end

  def in_set(_, []) do
    false
  end

  def in_set(policy, [%{valid_policy: policy} | _]) do
    true
  end

  def in_set(policy, [_ | rest]) do
    in_set(policy, rest)
  end

  def is_empty({}) do
    true
  end

  def is_empty(_) do
    false
  end

  def map_leaves({parent, [{_, _} | _] = childNodes}, leafFun) do
    {parent,
     :lists.map(
       fn childNode ->
         map_leaves(childNode, leafFun)
       end,
       childNodes
     )}
  end

  def map_leaves({parent, leaves}, leafFun) do
    {parent, :lists.map(leafFun, leaves)}
  end

  def prune_leaves({} = empty, _) do
    empty
  end

  def prune_leaves({_, _} = tree, policy) do
    leafFun = fn %{valid_policy: validPolicy} = node ->
      case validPolicy do
        ^policy ->
          false

        _ ->
          {true, node}
      end
    end

    filter_leaves(tree, leafFun)
  end

  def prune_tree({} = empty) do
    empty
  end

  def prune_tree({_, []}) do
    empty()
  end

  def prune_tree({root, childNodes}) do
    case prune_children(childNodes) do
      [] ->
        empty()

      newChildNodes ->
        {root, newChildNodes}
    end
  end

  def prune_invalid_nodes(tree, []) do
    tree
  end

  def prune_invalid_nodes({root, childNodes}, invalidNodes) do
    case prune_invalid_nodes_children(
           childNodes,
           invalidNodes
         ) do
      [] ->
        empty()

      newChildNodes ->
        {root, newChildNodes}
    end
  end

  def policy_node(validPolicy, qualifiers, expPolicySet) do
    qualifierSet =
      case qualifiers do
        :asn1_NOVALUE ->
          []

        _ ->
          qualifiers
      end

    %{valid_policy: validPolicy, qualifier_set: qualifierSet, expected_policy_set: expPolicySet}
  end

  def root() do
    {any_policy_node(), []}
  end

  defp collect_children_qualifiers(_, [], _) do
    []
  end

  defp collect_children_qualifiers(
         collect,
         [
           {%{expected_policy_set: set}, _} = childNode
           | childNodes
         ],
         policy
       ) do
    case :lists.member(policy, set) do
      true ->
        :lists.flatten(children_collect(collect, childNode))

      false ->
        collect_children_qualifiers(collect, childNodes, policy)
    end
  end

  defp collect_children_qualifiers(collect, childNodes, _) do
    :lists.flatten(children_collect(collect, childNodes))
  end

  defp children_collect(collect, {parent, childNodes}) do
    collect.(parent) ++
      children_collect(
        collect,
        childNodes
      )
  end

  defp children_collect(collect, [{_, _} = childNode | childNodes]) do
    children_collect(
      collect,
      childNode
    ) ++ children_collect(collect, childNodes)
  end

  defp children_collect(collect, leaves) do
    :lists.map(collect, leaves)
  end

  defp filter_leaves({parent, [{_, _} | _] = childNodes}, leafFun) do
    {parent,
     :lists.map(
       fn childNode ->
         filter_leaves(childNode, leafFun)
       end,
       childNodes
     )}
  end

  defp filter_leaves({parent, leaves}, leafFun) do
    {parent, :lists.filtermap(leafFun, leaves)}
  end

  defp prune_children(childNodes) when is_list(childNodes) do
    :lists.filtermap(
      fn
        {parent, children} ->
          case prune_nodes(parent, children) do
            {^parent, []} ->
              false

            {^parent, newChildren} ->
              {true, {parent, newChildren}}
          end

        leaf ->
          {true, leaf}
      end,
      childNodes
    )
  end

  defp prune_nodes(parent, children) do
    {parent, prune_children(children)}
  end

  defp handle_too_long_notice(qualifier) do
    try do
      :public_key.der_decode(:OTPUserNotice, qualifier)
    catch
      :error, _ ->
        r_UserNotice(
          noticeRef: :asn1_NOVALUE,
          explicitText: ~c"User Notice much too long, so value is ignored"
        )
    else
      r_OTPUserNotice(noticeRef: ref, explicitText: dispText) ->
        r_UserNotice(noticeRef: ref, explicitText: dispText)
    end
  end
end
