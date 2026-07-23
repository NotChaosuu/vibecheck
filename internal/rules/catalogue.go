package rules

func All() []Rule {
	var all []Rule
	all = append(all, secretRules()...)
	all = append(all, configRules()...)
	all = append(all, injectionRules()...)
	return all
}

func Count() int { return len(All()) }
